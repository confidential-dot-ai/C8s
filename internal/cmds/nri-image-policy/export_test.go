package nriimagepolicy

// CheckStartup runs the startup steps that stand between loading the node's
// config at path and the first container create: loading and validating it,
// and rendering the CDS pins and address handed to injected credential
// clients, into runtimeDir instead of the compiled runtime directory. A config
// that fails here is one containerd can create no container under.
func CheckStartup(path, runtimeDir string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	previous := enforcerRuntimeDir
	enforcerRuntimeDir = runtimeDir
	defer func() { enforcerRuntimeDir = previous }()
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSPins(); err != nil {
		return err
	}
	return p.prepareCDSAddress()
}

// RunIn runs the plugin as Run does, rendering the documents it hands
// injected credential clients into runtimeDir instead of the compiled
// runtime directory.
func RunIn(runtimeDir string, args []string) error {
	previous := enforcerRuntimeDir
	enforcerRuntimeDir = runtimeDir
	defer func() { enforcerRuntimeDir = previous }()
	return Run(args)
}
