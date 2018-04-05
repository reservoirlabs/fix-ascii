# Copyright 2018 Reservoir Labs

# DPD signature to attach the FIX analyzer to TCP connections

signature dpd_fix4_fixt {
	ip-proto == tcp
	payload /^8=FIXT?\.[0-9]\.[0-9]/
	enable "fix4_fixt"
}
