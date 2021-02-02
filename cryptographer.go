package cryptographer

// Encrypter ...
type Encrypter interface {
	Encrypt(filenameSource, filenameDestination string)
}

// Decrypter ...
type Decrypter interface {
	Decrypt(filenameSource, filenameDestination string)
}

// Cryptographer ...
type Cryptographer interface {
	Encrypter
	Decrypter
}
