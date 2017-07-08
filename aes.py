#!/usr/bin/env python3
import copy
import os

'''
#############################################################################################################
						CONSTANT VALUES
#############################################################################################################
'''	

forward_s_box = [[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
	
inverse_s_box = [[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]

Rcon = [[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
		[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
		[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
		[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]]

multiplication_matrix = [	[2,3,1,1],
				[1,2,3,1],
				[1,1,2,3],
				[3,1,1,2]]

'''
#############################################################################################################
						HELPER FUNCTIONS
#############################################################################################################
'''				
			
# arrange 16 byte block of data in a 4x4 matrix
# writing vertically							
def block2matrix( block ):
	matrix = [[],[],[],[]]
	for i in range(len(block)):
		matrix[i%4].append(block[i])
	return matrix

# transform 4x4 matrix to 16 byte block of data	
def matrix2block( matrix ):
	block = []
	
	for i in range(4):
		for j in range(4):
			block.append(matrix[j][i])
	return block
	
def transpose_row_vector( row_vector ):
	column_vector = []
	for row in row_vector:
		column_vector.append(row[0])
	return column_vector
	
def transpose_column_vector( column_vector ):
	row_vector = []
	for column in column_vector:
		row_vector.append( [column] )
	return row_vector
	
def transpose_matrix( matrix ):	
	new_matrix = []
	for j in range(4):
		new_matrix.append([])
		for i in range(4):
			new_matrix[j].append(matrix[i][j])
	return new_matrix

def transpose( data ):
	if len(data) > 1:
		try:
			# if successful -> it's 2D array
			if len(data[0]) > 1:
				return transpose_matrix(data)
			elif len(data[0]) == 1:
				return transpose_row_vector(data)
		except:
			return transpose_column_vector(data)
	
def get_row(matrix, row_num):
	row = copy.deepcopy( matrix[ row_num ] )
	return row

def get_column(matrix, column_num ):
	column = []
	for row in matrix:
		column.append( [row[column_num]] )
	return column

def set_row(matrix, row_num, row_value):
	new_matrix = copy.deepcopy(matrix)
	new_matrix[row_num] = copy.copy(row_value)
	return new_matrix

def set_column(matrix, column_num, column_value):
	new_matrix = copy.deepcopy(matrix)
	for i in range(len(new_matrix)):
		new_matrix[i][column_num] = column_value[i][0]
	return new_matrix

# rotate 'n' times a list of 4 bytes 	
def rotate_word( word, n ):
	new_word = copy.deepcopy(word)
	for i in range(n):
		new_word = copy.deepcopy(new_word[1:] + [new_word[0]])
	return new_word

def xor( vector1, vector2):
	new_vector = []
	for i in range(4):
		new_vector.append( vector1[i] ^ vector2[i] )
	return new_vector

'''
#############################################################################################################
						AES FUNCTIONS
#############################################################################################################
'''				

	
# The AES key schedule algorithm
# Generates another 10 keys from the input key	
# The keys are 4x4 matrices
def key_schedule( input_key ):
	# round_keys is array of 4x4 matrices
	# The 0th key is our input key
	round_keys = [ copy.deepcopy( input_key ) ]
	
	for round in range(10):
		round_key = [] # holds the round key that is being generated
		# The new keys are generated one column at a time
		# One key has 4 columns -> loop 4 times
		for i in range(4):
			# If calculating the first column of a key
			if i == 0:
				# Get the last column of the previous key
				last_column = rotate_word( transpose( get_column(round_keys[round], 3) ), 1)
				
				column1 = []
				# substitute the bytes in 'last_column' using the s-box
				for j in last_column:
					low_nibble = j & 0x0f
					high_nibble = j >> 4
					column1.append( forward_s_box[high_nibble][low_nibble] )
			else:
				# get the last calculated column
				column1 = copy.deepcopy( round_key[i-1] )
			
			# get the i-th column of the previous key
			column2 = transpose(get_column(round_keys[round], i))
			# the current key column = column1 xor column2
			key_column = xor(column2, column1)
			
			# If calculating the first column of a key
			if i == 0:
				# get the 'round'-th column of Rcon matrix
				round_word = transpose( get_column(Rcon, round) )
				# the current key column = column1 xor column2 xor Rcon[round]
				key_column = xor( key_column, round_word )
			
			round_key.append( key_column )
		round_keys.append( transpose(round_key) )
	return round_keys			
		
# xor the columns of 'matrix' with the columns of 'round_key'
def add_round_key(matrix, round_key):
	new_matrix = []
	for i in range(4):
		m_column = transpose( get_column(matrix, i) )
		k_column = transpose( get_column(round_key, i))
		r_column = xor(m_column, k_column)
		new_matrix.append( r_column )
	return transpose(new_matrix)

# substitute the bytes in matrix with the corresponding value
# from the substitution box (s-box)
# most significant nibble indicates the row
# least significant nibble indicates column
# Ex. The byte 0x68 will be replaced with the value at
# row 6 and column 8 from the s-box	
def sub_bytes( matrix ):
	new_matrix = copy.deepcopy( matrix )
	for i in range(4):
		for j in range(4):
			low_nibble = matrix[i][j] & 0x0f
			high_nibble = matrix[i][j] >> 4
			new_matrix[i][j] = forward_s_box[high_nibble][low_nibble]
	return new_matrix

# rotates the n-th row n times
# 0th row is not shifted
# 1st row is rotated 1 time
# 2nd row is rotated 2 times
def shift_rows( matrix ):
	new_matrix = []
	for i in range(4):
		new_matrix.append( rotate_word( matrix[i], i) )
	return new_matrix

# A multiplication in Rijndael's Galois Field (GF)	
# The algorithm is as described here
# https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication
def multiply(a,b):
	p = 0
	for i in range(8):
		if b%2 != 0:
			p = p ^ a
		b = b >> 1
		carry = a >> 7
		a = a << 1
		if carry == 1:
			a = a ^ 0x11b
	return p

# The addition is just XOR	
def add( list_with_numbers ):
	result = 0
	for i in list_with_numbers:
		result ^= i
	return result
	
# Multiplies every column of matrix with 
# the 'multiplication_matrix' in Rijndael's Galois Field
def mix_columns( matrix ):
	new_matrix = []
	
	for c in range(4):
		# get each column of matrix
		column = transpose( get_column(matrix, c) )
		vector = [] # stores the final column
		for i in range(4):
			numbers = [] # stores the results of the multiplication
			# numbers = multiplication_matrix * column
			for j in range(4):
				numbers.append( multiply(multiplication_matrix[i][j], column[j]) )
			# the xor of all numbers
			r = add(numbers) 
			vector.append(r)
		# add the calculated vector as row to new_matrix (transpose to make rows columns)
		new_matrix.append(vector)
	return transpose(new_matrix)


'''
#############################################################################################################
					ENCRYPTION ALGORITHM
#############################################################################################################
'''				

def encrypt(input_matrix, key_matrix):
	round_keys = key_schedule( key_matrix )
	# at the 0th round xor input_matrix with the input_key
	state = add_round_key(input_matrix, round_keys[0])
	for i in range(1,10):
		# repeat 9 times
		state = sub_bytes(state)
		state = shift_rows(state)
		state = mix_columns(state)
		state = add_round_key(state, round_keys[i])
	# the last (10th) round
	state = sub_bytes(state)
	state = shift_rows(state)
	# the last (10th) round doesn't have mix_columns
	state = add_round_key(state, round_keys[10])
	return state

'''
#############################################################################################################
						PLAYGROUND
#############################################################################################################
'''				
def pkcs7_pad( text ):
	return text + bytes(chr(16 - len(text)%16),'ascii') * (16 - len(text)%16)	
	
k = bytes( os.urandom(16) )
print('Key: ',k)
key_matrix = block2matrix( list(k) )
	
# 16 byte input
text = b'test data'
padded_text = pkcs7_pad(text)

input_matrix = block2matrix( padded_text )

output_matrix = encrypt(input_matrix, key_matrix)
ciphertext = bytes( matrix2block( output_matrix ) )
print('Ciphertext: ', ciphertext)
