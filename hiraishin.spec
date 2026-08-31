# hiraishin.spec -- Crystal Palace spec for Hiraishin WorkMask PICO
#
# Builds the WorkMask runtime + protected functions as a single PICO module.
# The PICO provides encrypt-at-rest services via exported functions.
#
# Usage: java -jar crystalpalace.jar buildPic ./hiraishin.spec x64 bin/hiraishin.pico.bin

name "Hiraishin WorkMask PICO"
author "Hiraishin"

x64:
    # Load the WorkMask runtime (go, enter, exit, suspend, resume)
    load "bin/workmask.x64.o"
    make object +gofirst
    dfr ror13

    # Export the public API via ror13 hash tags
    exportfunc workmask_enter   wm_enter
    exportfunc workmask_exit    wm_exit
    exportfunc workmask_suspend wm_suspend
    exportfunc workmask_resume  wm_resume

    # Load protected functions (bodies encrypted post-link)
    load "bin/protected_funcs.x64.o"
    merge

    # Produce the PICO blob
    export
