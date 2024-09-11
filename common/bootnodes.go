package common

var (
	BootstrapPeers = map[string][]string{
		"colosseum": {
			"/dns4/bootnode.colosseum0.quai.network/tcp/4001/p2p/12D3KooWK3nVCWjToi3igfs8oyJscVQYLd4SmQanohAuF8M6eZBn",
		},
		"garden": {
			"/dns4/bootnode.garden0.quai.network/tcp/4001/p2p/12D3KooWRQrLVEeJtfyKoJDYWYjryBKR8qxkDooMMzyf2ZpLaZRR",
			"/dns4/bootnode.garden1.quai.network/tcp/4001/p2p/12D3KooWSb49ccXFWPCsvi7rzCbqBUK2xfuRC2xbo6KnUZk3YaVg",
			"/dns4/bootnode.garden2.quai.network/tcp/4001/p2p/12D3KooWR3xMB6sCpsowQcvtdMKmKbTaiDcDFAXuWABdZVPWaVuo",
			"/dns4/bootnode.garden3.quai.network/tcp/4001/p2p/12D3KooWJnWmBukEbZtGPPJvT1r4tQ97CRSGmnjHewcrjNB8oRxU",
		},
		"orchard": {
			"/ip4/34.136.175.169/tcp/4001/p2p/12D3KooWNN1TqsrEEmitkk1LefwLNgut621sSCdncPoyMVoYT1v4",
			"/ip4/34.122.101.50/tcp/4001/p2p/12D3KooWBAkaxYwJUenjVQPyvtZx6XWjtosyVzBRJxM7wthbWRE5",
			"/ip4/34.23.101.139/tcp/4001/p2p/12D3KooWBv5C4tSS72nBdG6Q12s7vSHYHtFcquBxAKDkfrrzseUz",
		},
		"lighthouse": {
			// "/dns4/host-go-quai/tcp/4001/p2p/12D3KooWS83uhvCfyNeAV24nEsp3DHrygDD39rZiVy6Gabv6pqxt",
			"/ip4/34.27.106.110/tcp/4001/p2p/12D3KooWAdPjwkuSoVN5CTTBZsTA9d9ASEJNDEcior6QvfLfbtz8",
			"/ip4/34.68.118.43/tcp/4001/p2p/12D3KooWJkKnVLUWcV2QiporsN8sPjnpyCYcnw8URzJiCeojLKvd",
		},
	}
)
