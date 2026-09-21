package schema

#ProjectSpec & {
	schema_version: "v1.0"
	id:             "01a07319-d64c-70bb-8f75-2b6780e17060"
	slug:           "crypto55"
	name:           "crypto55"
	intention:      "crypto55 : Client d'exécution et rollup L2 haute performance en pur Go 1.27 SIMD (0-CGO)"
	pole:           "devhoros"
	parent_slug:    "metiers"
	mounts: [
		{
			path:      "/devhoros/crypto55"
			partition: "/devhoros"
			role:      "code"
			shared:    false
		},
	]
	rules: [
		"evm-onestep-execution",
		"zero-cgo",
	]
	desks: []
	created_at: "2026-09-05T19:44:28Z"
}
