# function for permutation tacking p-box,binary string to be permuted and length of binary string as input
# and returning permuted binary string as a output
def permute(p,s,l):
    ns=''                  
    for i in range(l):
        ns += s[p[i] - 1]
    return ns

# function for left circular shift operation tackin binary string and its length as input
# and returning shifted binary string as a output
def lcs(ss,n):
    rlcs=''                  
    for i in range(len(ss)):
        rlcs+=ss[(n+i)%5]
    return rlcs

#function for diving string tackin binary string and and divider number as input and
#returning splited binary strings
def spliter(s,d):
    split1=s[0:d]
    split2=s[d:]
    return(split1,split2)

#key generator function
def keygenerator(p10,p8,key):
    keyp = permute(p10, key, 10)

    ls1, ls2 = spliter(keyp, 5)

    ls1 = lcs(ls1, 1)
    ls2 = lcs(ls2, 1)
    ls = ls1 + ls2
    k1 = permute(p8, ls, 8)

    ls1 = lcs(ls1, 2)
    ls2 = lcs(ls2, 2)
    ls = ls1 + ls2
    k2 = permute(p8, ls, 8)

    return(k1,k2)

#function for doing xor operation between two strings and tacking two binary strings and and it's length as input and
#returning binary string output of two strings
def doxor(s1,s2,l):
    c = ''                          
    for i in range(l):
        c = c + str(int(s1[i]) ^ int(s2[i]))
    return c

#function for converting binary string into integer number
def stoi(sdata):
    return int(sdata,2)

#function for returning indexes for s-boxes
def giveindex(data):
    r=stoi(data[0]+data[3])
    c=stoi(data[1]+data[2])
    return (r,c)


#START OF SDES ENCRYPTION ALGORITHM
def sdes_encryption(plaintext,key,ip,ep,s1,s2,p4,p10,p8):
    ipinv = []
    for i in range(8):  # Finding inverse of ip
        ipinv.append(ip.index(i + 1) + 1)

    key1, key2 = keygenerator(p10, p8, key)
    plaintextip = permute(ip, plaintext, 8)

    l0, r0 = spliter(plaintextip, 4)

    # Round 1
    u_r0 = permute(ep, r0, 8)  # Expansion Permutation
    xorout = doxor(u_r0, key1, 8)  # XOR operation with key
    sbx1, sbx2 = spliter(xorout, 4)  # Spliting of output of xor operation
    r1r1, r1c1 = giveindex(sbx1)  # Getting index for sbox s1 & s2 from splited string
    r1r2, r1c2 = giveindex(sbx2)
    u_r0 = s1[r1r1][r1c1] + s2[r1r2][r1c2]  # Getting according data from s-boxes
    u_r0 = permute(p4, u_r0, 4)  # Last 4 bit permutation
    # end of Round 1

    r1 = doxor(l0, u_r0, 4)  # Swaping for Round-2
    l1 = r0

    # Round 2
    u_r1 = permute(ep, r1, 8)  # Expansion Permutation
    xorout = doxor(u_r1, key2, 8)  # XOR operation with key
    sbx1, sbx2 = spliter(xorout, 4)  # Spliting of output of xor operation
    r2r1, r2c1 = giveindex(sbx1)  # Getting index for sbox s1 & s2 from splited string
    r2r2, r2c2 = giveindex(sbx2)
    u_r1 = s1[r2r1][r2c1] + s2[r2r2][r2c2]  # Getting according data from s-boxes
    u_r1 = permute(p4, u_r1, 4)  # Last 4 bit permutation
    u_r1 = doxor(u_r1, l1, 4)
    # end of Round 2

    last = u_r1 + r1
    ciphertext = permute(ipinv, last, 8)  # Permutation with inverse of initial permutation(ip)
    return ciphertext
#END OF SDES ENCRYPTION ALGORITHM

#START OF SDES DECRYPTION ALGORITHM

def sdes_decryption(ciphertext,key,ip,ep,s1,s2,p4,p10,p8):
    ipinv = []
    for i in range(8):  # Finding inverse of ip
        ipinv.append(ip.index(i + 1) + 1)

    key1, key2 = keygenerator(p10, p8, key)
    ciphertextipinv = permute(ip, ciphertext, 8)

    l0, r0 = spliter(ciphertextipinv, 4)

    # Round 1
    u_r0 = permute(ep, r0, 8)  # Expansion Permutation
    xorout = doxor(u_r0, key2, 8)  # XOR operation with key and use key2 for round1
    sbx1, sbx2 = spliter(xorout, 4)  # Spliting of output of xor operation
    r1r1, r1c1 = giveindex(sbx1)  # Getting index for sbox s1 & s2 from splited string
    r1r2, r1c2 = giveindex(sbx2)
    u_r0 = s1[r1r1][r1c1] + s2[r1r2][r1c2]  # Getting according data from s-boxes
    u_r0 = permute(p4, u_r0, 4)  # Last 4 bit permutation
    # end of Round 1

    r1 = doxor(l0, u_r0, 4)  # Swaping for Round-2
    l1 = r0

    # Round 2
    u_r1 = permute(ep, r1, 8)  # Expansion Permutation
    xorout = doxor(u_r1, key1, 8)  # XOR operation with key and use key1 for round2
    sbx1, sbx2 = spliter(xorout, 4)  # Spliting of output of xor operation
    r2r1, r2c1 = giveindex(sbx1)  # Getting index for sbox s1 & s2 from splited string
    r2r2, r2c2 = giveindex(sbx2)
    u_r1 = s1[r2r1][r2c1] + s2[r2r2][r2c2]  # Getting according data from s-boxes
    u_r1 = permute(p4, u_r1, 4)  # Last 4 bit permutation
    u_r1 = doxor(u_r1, l1, 4)
    # end of Round 2

    last = u_r1 + r1
    plaintextagain = permute(ipinv, last, 8)  # Permutation with inverse of initial permutation(ip)
    return plaintextagain

#END OF SDES DECRYPTION ALGORITHM

p10=[3,5,2,7,4,10,1,9,8,6]      #initial permutation box(p-box) for key
p8=[6,3,7,4,8,5,10,9]             #P-box for contaction permutation
p4=[2,4,3,1]        
ip=[2,6,3,1,4,8,5,7]                #initial permutation box
ep=[4,1,2,3,2,3,4,1]               #expansion permutation box
s1=[['01','00','11','10'],['11','10','01','00'],['00','10','01','11'],['11','01','11','10']]    #substitution-box 1
s2=[['00','01','10','11'],['10','00','01','11'],['11','00','01','00'],['10','01','00','11']]    #substitution-box 2
key='1010000010'
plaintext='11011000'            #First Input String '01100010'


print("Plain Text    : ",plaintext)
ciphertext=sdes_encryption(plaintext,key,ip,ep,s1,s2,p4,p10,p8)
print("Cipher Text  : ",ciphertext)
plaintextagain=sdes_decryption(ciphertext,key,ip,ep,s1,s2,p4,p10,p8)
print("Plaintext again : ",plaintextagain)
