nop 
mov x29, #0
mov x30, #0
mov x5, x0
ldr x1, [sp]
add x2, sp, #8
mov x6, sp
adrp x0, #0x1000
add x0, x0, #0x4f4
mov x3, #0
mov x4, #0
bl #0xfb0
bl #0xfd0
nop 
b #0x1130
nop 
ret 
adrp x0, #0x11000
ldr x0, [x0, #0xfe0]
cbz x0, #0x1054
b #0xfc0
ret 
nop 
nop 
adrp x0, #0x12000
add x0, x0, #0x30
adrp x1, #0x12000
add x1, x1, #0x30
cmp x1, x0
b.eq #0x108c
adrp x1, #0x1000
ldr x1, [x1, #0x650]
cbz x1, #0x108c
mov x16, x1
br x16
ret 
adrp x0, #0x12000
add x0, x0, #0x30
adrp x1, #0x12000
add x1, x1, #0x30
sub x1, x1, x0
lsr x2, x1, #0x3f
add x1, x2, x1, asr #3
asr x1, x1, #1
cbz x1, #0x10c8
adrp x2, #0x1000
ldr x2, [x2, #0x658]
cbz x2, #0x10c8
mov x16, x2
br x16
ret 
nop 
stp x29, x30, [sp, #-0x20]!
mov x29, sp
str x19, [sp, #0x10]
adrp x19, #0x12000
ldrb w0, [x19, #0x30]
cbnz w0, #0x10f4
bl #0x1060
mov w0, #1
strb w0, [x19, #0x30]
ldr x19, [sp, #0x10]
ldp x29, x30, [sp], #0x20
ret 
b #0x1090
sub sp, sp, #0x10
str w0, [sp, #0xc]
str w1, [sp, #8]
ldr w0, [sp, #0xc]
add w0, w0, #1
str w0, [sp, #0xc]
ldr w1, [sp, #0xc]
ldr w0, [sp, #8]
add w0, w1, w0
add sp, sp, #0x10
ret 
b #0x12c0
mov x29, sp
mov w0, #1
str w0, [sp, #0x14]
mov w0, #1
str w0, [sp, #0x18]
ldr w1, [sp, #0x18]
ldr w0, [sp, #0x14]
bl #0x1104
str w0, [sp, #0x1c]
adrp x0, #0x1000
add x0, x0, #0x660
bl #0xfe0
mov w0, #0
ldp x29, x30, [sp], #0x20
ret 
