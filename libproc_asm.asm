public payload
public __begin_of_code
injected segment read execute

__begin_of_code label BYTE
	payload proc

	nop
	_test:
	int 3
	nop

	_end:
	payload endp
injected ends

END