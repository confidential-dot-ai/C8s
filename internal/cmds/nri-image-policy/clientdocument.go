package nriimagepolicy

// renderedClientDocumentName is the guest-side file a Pod CVM's client
// document is bound from.
const renderedClientDocumentName = "client-document"

// prepareClientDocument writes the assignment's client document before any
// container can be created, so every container of the Pod can read it.
func (p *plugin) prepareClientDocument() error {
	if !p.cfg.podRole() || len(p.cfg.Pod.ClientDocument) == 0 {
		return nil
	}
	path, err := renderNodeDocument(renderedClientDocumentName, p.cfg.Pod.ClientDocument)
	if err != nil {
		return err
	}
	p.clientDocument = path
	return nil
}
