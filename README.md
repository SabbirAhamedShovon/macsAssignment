<p align="center">
  <img src="hstu_logo.png" alt="hstu_logo_.png" width="250" height="300">
</p>
<h1 align="center">
  <b>Encryption Algorithm</b>
</h1>
<h3 align="center">
  <br>
  <b>Level-3 Semester-II</b>  
</h3>
<h3 align="center">
  Course Code: CSE 361 
</h3>

<h3 align="center">
  Course Title: Mathematical Analysis for Computer Science
  
</h3>
<br>
<h3 align="center">
  Submitted by 
</h3>
<h3 align="center">
<b>Md. Sabbir Ahamed Shovon (ID: 2102034) </b> </h3>
<br>

<h3 align="center">
  Submitted To 
</h3>

<h3 align="center"><b>Pankaj Bhowmik  </b></h3>
<h3 align="center"><b>Lecturer, Department of CSE</b></h3>
<br>
<h3 align="center"> <b>Department of Computer Science and Engineering </b></h3>
<h3 align="center"><b>Hajee Mohammad Danesh Science and Technology University  
Dinajpur-5200</b></h3>




# Advanced Encryption Algorithm Using Number Theory Concepts

## Algorithm Overview
This encryption algorithm combines:
- GCD and co-prime numbers for key generation
- Bit masking for initial data transformation
- Permutation for position scrambling
- Euler's totient function for RSA-style encryption
- Chinese Remainder Theorem for decryption optimization

## Flow Charts

### Key Generation
<ol>
  <li>
    Select two large co-prime numbers <b>p</b> and <b>q</b>
    <ul>
      <li>Generate random numbers in a specified range</li>
      <li>Ensure gcd(p, q) = 1</li>
    </ul>
  </li>
  <li>
    Compute modulus <b>n</b> and Euler's totient &phi;(n)
    <ul>
      <li>n = p &times; q</li>
      <li>&phi;(n) = (p - 1) &times; (q - 1)</li>
    </ul>
  </li>
  <li>
    Choose public exponent <b>e</b>
    <ul>
      <li>Select e where 1 &lt; e &lt; &phi;(n) and gcd(e, &phi;(n)) = 1</li>
    </ul>
  </li>
  <li>
    Compute private exponent <b>d</b>
    <ul>
      <li>d = e<sup>-1</sup> mod &phi;(n) (modular inverse)</li>
    </ul>
  </li>
  <li>
    Generate permutation key
    <ul>
      <li>Create a random shuffle of byte positions (0–255)</li>
    </ul>
  </li>
  <li>
    Generate bitmask key
    <ul>
      <li>Create a random 256-bit mask</li>
    </ul>
  </li>
</ol>
<p align = "center">
 <img src="key.png" alt="hstu_logo_.png" width="400" height = "500">
</p>

### Encryption

<p align = "center">
 <img src="encryption.png" alt="hstu_logo_.png" width="400" height = "500">
</p>
 ### Decryption
 
  <div align = "center" ><img src="decryption.png" alt="hstu_logo_.png" width="400" height = "500"> </div>


### Key Generation


