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
// and starting the plugin, the Trust Authority being unreachable or restarted, and the
// version of the served allowlist. Everything a scenario does here is undone
// by restoreNode after it.
func registerNode(sc *godog.ScenarioContext) {
	sc.Step(`^the admission plugin on node "([^"]*)" stops$`, pluginStops)
	sc.Step(`^the admission plugin on node "([^"]*)" is not running$`, pluginStops)
	sc.Step(`^the admission plugin on node "([^"]*)" starts$`, pluginStarts)
	sc.Step(`^the admission plugin on node "([^"]*)" is ready$`, pluginIsReady)
	sc.Step(`^the (?:Trust Authority|CDS) cannot be reached from node "([^"]*)"$`, taUnreachable)
	sc.Step(`^the admission plugin on node "([^"]*)" has started since the (?:Trust Authority|CDS) became unreachable$`, pluginStartedSinceBlock)
	sc.Step(`^the first pull of the admission plugin on node "([^"]*)" has not succeeded$`, firstPullNotSucceeded)
	sc.Step(`^the admission plugin on node "([^"]*)" pulls the served allowlist$`, pluginPulls)
	sc.Step(`^the database of the (?:Trust Authority|CDS) does not survive a restart$`, taVolatile)
	sc.Step(`^the (?:Trust Authority|CDS) (?:restarts|has restarted)$`, taRestarted)
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
// sentence observes a plugin that has run its startup check. Where the Trust Authority is
// reachable it first waits for the last write to take effect on nodes, so
// the plugin's first pull is served it.
func pluginStarts(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	if !w.taBlocked {
		if _, _, err := w.awaitInEffect(); err != nil {
			return err
		}
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

// taUnreachable blocks every node's pull; the backend cannot block one
// node's, so the sentence's node only has to exist.
func taUnreachable(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.node(node); err != nil {
		return err
	}
	// Set first: a block that never settles may still have taken hold.
	w.taBlocked = true
	_, err := w.be.call("ta_block")
	return err
}

func pluginStartedSinceBlock(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if !w.taBlocked {
		return errors.New("the scenario has not made the Trust Authority unreachable")
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
	if !w.taBlocked {
		return errors.New("the Trust Authority is reachable, so the first pull may have succeeded")
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

// taVolatile skips where a Trust Authority restart keeps the allowlist and its version
// (allowlist S4).
func taVolatile(ctx context.Context) error {
	answer, err := getWorld(ctx).be.call("ta_volatile")
	if err != nil {
		return err
	}
	if answer != "yes" {
		return skipf("a Trust Authority restart keeps the allowlist here (ta_volatile)")
	}
	return nil
}

// taRestarted restarts the Trust Authority; what it serves afterwards is a change the
// plugin has yet to pull.
func taRestarted(ctx context.Context) error {
	w := getWorld(ctx)
	if _, err := w.be.call("ta_restart"); err != nil {
		return err
	}
	w.noteTARestart()
	return nil
}

// noteTARestart records a Trust Authority restart, however it came about: what it serves
// afterwards is a change the plugin has yet to pull, and restoring the node
// means starting the plugin again.
func (w *world) noteTARestart() {
	w.taRestarted = true
	// The restart replaced the document wholesale, so no write of this
	// process's is waiting to take effect on nodes.
	lastMutation.at = time.Now()
	lastMutation.documentTag = ""
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
	now, err := w.servedVersion()
	if err != nil {
		return err
	}
	if now >= applied {
		return fmt.Errorf("the served version is %d, not below the applied %d", now, applied)
	}
	return nil
}

// restoreNode undoes what the scenario did to the node and the Trust Authority: the pull
// is unblocked, and the plugin is started again where the scenario stopped
// it, or on every node it addressed and on node "one" if the Trust Authority was
// restarted, since only a start lets a plugin accept the versions a
// restarted Trust Authority serves, whether or not the scenario spoke of its node. After
// a Trust Authority restart the mesh members are recreated too: only a member started
// after the Trust Authority holds a leaf under the mesh CA it minted.
func (w *world) restoreNode() error {
	var errs []error
	if w.taBlocked {
		_, err := w.be.call("ta_unblock")
		errs = append(errs, err)
	}
	if w.taRestarted {
		if k8sNode, err := w.be.call("node_name", "one"); err == nil {
			w.nodes[k8sNode] = true
		}
	}
	for k8sNode := range w.nodes {
		if !w.pluginDown[k8sNode] && !w.taRestarted {
			continue
		}
		_, err := w.be.call("plugin_start", k8sNode)
		errs = append(errs, err)
	}
	if w.taRestarted {
		_, err := w.be.call("mesh_restart")
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
