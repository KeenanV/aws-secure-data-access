# Double Ratchet Communication Voting System

## Intro

The Double Ratchet Communication Voting System was created to be a critical element of a 3rd-party system in control of
secure access control for AWS resources, specifically S3 Buckets. As a part of this system, three servers owned by the
3rd party will be communicating with each other and host the user accounts for managing and modifying bucket policies.
All communication will happen through channels with two layers of encryption. The first layer, users, are using Double
Ratchet with X25519 Diffie Hellman for encrypting and decrypting their messages. The second layer, servers, are using
symmetric encryption with X25519 for encrypting and decrypting packets, providing confidentiality. The Ed25519 signing
scheme is then used for signing packets to provide integrity and authentication. Before any policy changes can be made,
these three servers must agree that the changes are correct before they are committed. This improves resilience against
adversaries, detection speed of a breach or compromise, and reduces the amount of destruction caused by a breach. These
designs aim to ensure separate accounts and users are used for each bucket and object(s) to reduce the area of
destruction if one of them happened to be breached. Additionally, the added accounts in Design 2 aim to ensure faster
breach detection, elimination, and recovery. The first Design Modification would speed up the elimination and recovery
even more. Finally, by allowing the customer to be the bucket owner, it gives them ultimate control over everything
which can give them peace of mind.

## Designs

### Design 1:

- Customer owns all buckets, each with a different account
    - Bucket owner sets Block Public Access bucket policy which acts as an explicit deny (overrides any public access
      policies) so the buckets can never by accessed publicly even if Codified is breached
    - Bucket owner creates Codified users, one for each object/set of objects in the bucket
    - Bucket owner gives each Codified user minimum permissions to read/write and set/delete policies for their objects
    - Bucket owner does not give Codified users ChangePassword permissions (attacker could therefore not lock out
      Codified by changing the users’ passwords)
- All users must require MFA for sign-in using a YubiKey as their second factor
- Codified users would make requests using access keys
    - Access keys would be changed after every request
- Bucket owner can change Codified users’ passwords as often as they prefer (once a week, once a day, etc.)

### Design 2:

- Same as Design 1 except three Codified users are created for each object/set of objects in the bucket instead of one
    - One account has read/write permissions and two have permissions to read the policy lists
- The two read accounts will each exist on their own network and be accessed through separate hardware
- When a permissions request is sent to Codified, it is received by all three users
    - If the request is approved, all three users will send confirmation to each other using secure Double Ratchet ECDH
      channels and ensure a unanimous vote is received
    - If a unanimous vote is not received, the user(s) that did not vote are flagged as compromised and the customer is
      notified to delete those accounts
    - The read accounts are constantly scanning the policy lists for the objects they have access to to ensure no
      unapproved changes (not voted on unanimously)
    - If unapproved changes are noticed, a notification is sent to the customer to deactivate the write account and
      transfer write permissions to one of the read accounts

### Design Modifications (Optional):

- An additional layer can be added between the bucket owner account and the Codified users by adding another account
    - This account would be owned by Codified and given all necessary permissions by the bucket owner (customer)
    - This account would also control all the Codified users and automatically reset their passwords daily
    - This account could only be signed into with a YubiKey that requires a fingerprint which means a password, physical
      device, and biometrics are required for authentication, making it incredibly difficult to breach
    - This account could deactivate Codified user accounts immediately if one is compromised, removing the requirement
      of the customer to carry out this action
- A bucket policy can be set by the bucket owner to restrict access to specific IPs (Codified and customer) if it works
  with the required behavior of the bucket

## Usage

This project has been built in accordance with Design 2, outlined above. Below are three ways to test this system and
one method of implementation.

### Basic CLI User Input Chat

To test the functionality of the communications, the user to run two server instances and send messages back and forth.
**TODO**

### Voting System Demo

**TODO**

### Unit Tests

**TODO**

### Implementation

**TODO**
