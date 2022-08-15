# T.D.P
Thread Description Poising; Using Thread Description To Hide Shellcodes

# HOW DOES IT WORK:
* first thing, is to load the function `load_shellcode` that will hook sleep and set a VEH handler (that will be used to know when sleep is done)
* next we need to do, is to run the shellcode, im using [CreateTimerQueueTimer](https://gitlab.com/ORCA666/t.d.p/-/blob/main/TDP/main.c#L33) function to do that
* when the shellcode is executed, in our case, cobalt strike, it will go to sleep, when we detect sleep function, the shellcode in memory is encrypted with a xor key (different one each cycle)
* TDP then will set permissions of the memory holding the shellcode to `PAGE_NOACCESS`, and store an encrypted shellcode in a thread's description, after changing it to `UTF-16` encoding so that it can be stored.
* then the base address in which the shellcode is placed will be set to zero [here](https://gitlab.com/ORCA666/t.d.p/-/blob/main/TDP/Hook.hpp#L194) 
* what we have now is a clean memory and a random thread holding our encrypted shellcode
* here, i added extra spice, using [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer/tree/master/ThreadStackSpoofer), and i unhooked sleep (re-hook it later), thats to not look so sus by hooking apis
* when the sleep is done, we read the shellcode from the thread description, decrypt it, and set the permissions to `PAGE_EXECUTE_READWRITE`, change the shellcode's bytes to `multibyte string` and then ...
* paste it back to the base address, re-hook sleep and let the payload do its job, we do everything from the start till the session/connection is closed ...


# THANKS FOR:
* [ThreadDescription](https://github.com/gtworek/PSBits/tree/master/ThreadDescription)
* [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer/tree/master/ThreadStackSpoofer)

# AT THE END:
#### This is Not A Code meant to bypass anti virus products directly, but a step to do so, In case you have any questions/ problems, let me know that and i will be more than happy to help.
