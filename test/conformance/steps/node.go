package steps

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about the admission plugin's lifetime and its source: stopping
// and starting the plugin, the CDS being unreachable or restarted, and the
// version of the served allowlist. Everything a scenario does here is undone
// by restoreNode after it.
func registerNode(sc *godog.ScenarioContext) {
	sc.Step(`^the admission plugin on node "([^"]*)" stops$`, pluginStops)
	sc.Step(`^the admission plugin on node "([^"]*)" is not running$`, pluginStops)
	sc.Step(`^the admission plugin on node "([^"]*)" starts$`, pluginStarts)
	sc.Step(`^the admission plugin on node "([^"]*)" is ready$`, pluginIsReady)
	sc.Step(`^the CDS cannot be reached from node "([^"]*)"$`, cdsUnreachable)
	sc.Step(`^the admission plugin on node "([^"]*)" has started since the CDS became unreachable$`, pluginStartedSinceBlock)
	sc.Step(`^the first pull of the admission plugin on node "([^"]*)" has not succeeded$`, firstPullNotSucceeded)
	sc.Step(`^the admission plugin on node "([^"]*)" pulls the served allowlist$`, pluginPulls)
	sc.Step(`^the database of the CDS does not survive a restart$`, cdsVolatile)
	sc.Step(`^the CDS has restarted$`, cdsRestarted)
	sc.Step(`^the version of the served allowlist is below the version the admission plugin on node "([^"]*)" applied$`, versionBelowApplied)
}

// node resolves a scenario's node and remembers that the scenario addressed
// its plugin.
func (w *world) node(name string) (string, error) {
	k8sNode, err := w.be.call("node_name", name)
	if err != nil {
		return "", err
	}
	w.nodes[k8sNode] = true
	return k8sNode, nil
}

func pluginStops(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	if _, err := w.be.call("plugin_stop", k8sNode); err != nil {
		return err
	}
	w.pluginDown[k8sNode] = true
	return nil
}

// pluginStarts starts the plugin and waits until it is ready, so the next
// sentence observes a plugin that has run its startup check.
func pluginStarts(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	if _, err := w.be.call("plugin_start", k8sNode); err != nil {
		return err
	}
	delete(w.pluginDown, k8sNode)
	return nil
}

func pluginIsReady(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	_, err = w.be.call("plugin_ready", k8sNode)
	return err
}

// cdsUnreachable blocks every node's pull; the backend cannot block one
// node's, so the sentence's node only has to exist.
func cdsUnreachable(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.node(node); err != nil {
		return err
	}
	if _, err := w.be.call("cds_block"); err != nil {
		return err
	}
	w.cdsBlocked = true
	return nil
}

func pluginStartedSinceBlock(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if !w.cdsBlocked {
		return errors.New("the scenario has not made the CDS unreachable")
	}
	if err := pluginStops(ctx, node); err != nil {
		return err
	}
	return pluginStarts(ctx, node)
}

// firstPullNotSucceeded holds as long as the pull stays blocked; the
// sentence states the precondition the scenario relies on.
func firstPullNotSucceeded(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.node(node); err != nil {
		return err
	}
	if !w.cdsBlocked {
		return errors.New("the CDS is reachable, so the first pull may have succeeded")
	}
	return nil
}

// pluginPulls waits for a pull to have happened since the last change the
// scenario made, as the applied sentence does, but writes nothing.
func pluginPulls(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.node(node); err != nil {
		return err
	}
	return w.awaitApplied()
}

func cdsVolatile(ctx context.Context) error {
	answer, err := getWorld(ctx).be.call("cds_volatile")
	if err != nil {
		return err
	}
	if answer != "yes" {
		return godog.ErrSkip
	}
	return nil
}

// cdsRestarted restarts the CDS; what it serves afterwards is a change the
// plugin has yet to pull.
func cdsRestarted(ctx context.Context) error {
	w := getWorld(ctx)
	if _, err := w.be.call("cds_restart"); err != nil {
		return err
	}
	w.cdsRestarted = true
	lastMutation = time.Now()
	return nil
}

func versionBelowApplied(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.node(node); err != nil {
		return err
	}
	if w.appliedVersion == "" {
		return errors.New("the scenario has not waited for the plugin to apply a served allowlist")
	}
	applied, err := strconv.Atoi(w.appliedVersion)
	if err != nil {
		return fmt.Errorf("applied version %q: %w", w.appliedVersion, err)
	}
	s, err := w.be.call("served_version")
	if err != nil {
		return err
	}
	now, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("served version %q: %w", s, err)
	}
	if now >= applied {
		return fmt.Errorf("the served version is %d, not below the applied %d", now, applied)
	}
	return nil
}

// restoreNode undoes what the scenario did to the node and the CDS: the pull
// is unblocked, and the plugin is started again where the scenario stopped
// it, or wherever it addressed one if the CDS was restarted, since only a
// start lets the plugin accept the versions a restarted CDS serves.
func (w *world) restoreNode() error {
	var errs []error
	if w.cdsBlocked {
		_, err := w.be.call("cds_unblock")
		errs = append(errs, err)
	}
	for k8sNode := range w.nodes {
		if !w.pluginDown[k8sNode] && !w.cdsRestarted {
			continue
		}
		_, err := w.be.call("plugin_start", k8sNode)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
