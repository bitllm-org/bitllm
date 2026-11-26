package aci

// DefaultPolicy is the set of TEE builds this release trusts. Each entry is a
// build of Dstack-TEE/private-ai-gateway on a dstack OS image, as served by
// tee.redpill.ai. A new build there is refused until a release adds it here:
// read its compose (the report's app_compose) and commit before adding.
var DefaultPolicy = Policy{Accept: []Measurements{
	{
		Name:        "private-ai-gateway 9f3e693 on dstack-0.5.12 (tee.redpill.ai, 2026-11-25)",
		MRTD:        "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
		RTMR1:       "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
		RTMR2:       "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
		ComposeHash: "f7136328f40a78a102ecebf9ccdbfd5cdf7f446fb42ddfe0b41e3dc8ddd7ace1",
	},
}}
