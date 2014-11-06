# Release pyRadamsa

### Modes

* default mutators in radamsa
* setting/detecting type of data
* entropy maintaining
* zalgo mode
* vectors for various data types

### Radamsa mutators

#### [b]yte (single)

* drop a byte
* flip one bit
* insert a random byte
* repeat a byte
* permute some bytes
* increment a byte by one
* decrement a byte by one
* swap a byte with a random one

#### [s]equence of bytes

* repeat a sequence of bytes

#### line

* delete a line
* duplicate a line
* clone and insert it nearby
* repeat a line
* swap two lines
* swap order of lines

#### tree

* delete a node
* duplicate a node
* swap one node with another one
* swap two nodes pairwise
* repeat a path of the parse tree

#### utf-8

* try to make a code point too wide
* insert funny unicode

#### special

* modify a textual number

#### suffix (aka fuse)

* jump to a similar position in block
* likely clone data between similar positions
* fuse previously seen data elsewhere
