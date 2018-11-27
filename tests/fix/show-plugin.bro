# @TEST-EXEC: bro -NN RLABS::FIX |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
