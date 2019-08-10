# multikey - secrets framework

Example use cases:

- I want anyone on my team to be able to decrypt shared application runtime secrets with their own key locally, and have my deployments be able to decrypt the same secrets by fetching a decryption key from AWS KMS
- I want my team to be able to access a highly privileged secret in emergency situations, by having n/N team members provide their key

... many more
