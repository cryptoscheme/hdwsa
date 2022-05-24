# HDWSA
The Experimental Implementation of the Secure Hierarchical Deterministic Wallet Supporting Stealth Address.

# Prerequisites

   System requirement: Linux   
   Go version: 1.16.8   
   Library requirement: have [PBC](https://crypto.stanford.edu/pbc/download.html) and [GMP](https://gmplib.org/) installed. 
   
# Test
To download, run stathdwsa.sh in hdwsa, follow the following steps:
  
  git clone https://github.com/cryptoscheme/hdwsa
  
  cd hdwsa
  
  ./stathdwsa.sh 

# Details of Test

  We use a type A pairing on an elliptic curve y^2 = x^3 + x over Fq for 512-bit q and group with 160-bit prime order, 
  and sha-256 for hashing. 
   
# Introduction of Source Files

   hdwsa.go: the implementation of all used functions in our hdwsa.
   
   types.go: the data models.
   
   hdwsa_test.go: the functioning test and benchmark logic here. 
   
   stathdwsa.sh: the scripts for running the test, extracting the result and final calculation all in one.  
