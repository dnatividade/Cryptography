## Diffie-Hellman example:


### Node [A]
```
Parameters:
g= 957
p= 113
kA=11
```

```
Equation:
(g^kA) MOD p = qA
get: qB
(qB^qA) mod p = K
```
---

### Node [B]
```
Parameters:
g= 957
p= 113
kB=17
```

```
Equation:
(g^kB) MOD p = qB
get: qA
(qA^qB) mod p = K
```

---

SOURCE: https://pt.khanacademy.org/computing/computer-science/cryptography/modern-crypt/v/diffie-hellman-key-exchange-part-2
