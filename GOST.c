#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/random.h>

int GLOBAL_INDEX_ROUNDS = 0;
int BLOCK_LENGTH = 64;
int KEY_LENGTH = 256;
int S_BOXES[8][16] = {{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
                      {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
                      {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
                      {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
                      {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
                      {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
                      {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
                      {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}};
uint32_t power_2_32_min_1 = 4294967295;
uint32_t s_box_masks[8] = {4026531840, 251658240, 15728640, 983040, 61440, 3840, 240, 15};

uint64_t generate_iv(){
	uint64_t iv;
	getrandom(&iv, sizeof(uint64_t), GRND_NONBLOCK);
	return iv;
}

uint32_t s_box_half_block_in(uint32_t half_block){
        uint32_t result = 0;
        for (int i = 0; i < 8; i++){
        	// half_block AND mask => only 4 bits remain, then rotate these bits so that they are the last 4 of the 32
                uint32_t s_box_pass = S_BOXES[i][(half_block & s_box_masks[i]) >> (28 - 4*i)];
                // the 4 bit result must be shifted to the right so that bits stack up correctly
		s_box_pass = s_box_pass << (28 - 4*i);
		result = result | s_box_pass;
        }
        return result;
}

void f_round(uint32_t *msg_hi, uint32_t *msg_lo, uint32_t *sub_key){
	uint32_t tmp = *msg_lo;
	// (msg_lo + sub_key) % 2^32 == (msg_lo + sub_key) AND 2^32 - 1
	// both operands are 32 bits, they must be casted to 64 bit to avoid overflow and then casted back
	uint32_t modulo2sum = (uint32_t) (((uint64_t) *msg_lo + (uint64_t) *sub_key) & power_2_32_min_1);
	modulo2sum = s_box_half_block_in(modulo2sum);
	modulo2sum = (modulo2sum << 11) | (modulo2sum >> 21);
	*msg_lo = modulo2sum ^ *msg_hi;
	*msg_hi = tmp;
}

uint64_t encrypt_block(uint64_t block, uint32_t sub_keys[]){
	// msg_hi is obtained by rotating to the right the first 32 bits of the block
	// notice the parenthesis => first rotate the 64 bit int right by 32, then cast the result tu uint32_t
	uint32_t msg_hi = (uint32_t) (block >> 32);
	uint32_t *msg_hi_ptr = &msg_hi;
	// msg_lo is obtained by rotating to the right the last 32 bits of the block, and then shifted again of 32 positions
	uint32_t msg_lo = (uint32_t) ((block << 32) >> 32);
	uint32_t *msg_lo_ptr = &msg_lo;
	uint32_t *sub_key_ptr;
	// these are normal GOST cycles done per each block
	for (int i = 0; i < 24; i++){
		sub_key_ptr = &sub_keys[i % 8];
		f_round(msg_hi_ptr, msg_lo_ptr, sub_key_ptr);
	}
	for (int i = 8; i > 0; i--){
		sub_key_ptr = &sub_keys[i - 1];
		f_round(msg_hi_ptr, msg_lo_ptr, sub_key_ptr);
	}
	// to return a 64 bit block, simply cast msg_hi to uint64_t, rotate to the left by 32 and then add msg_lo (casted to uint64_t too)
	return ((uint64_t) msg_lo) << 32 | (uint64_t) msg_hi;
}

void encrypt(uint64_t blocks[], int blocks_len, uint32_t sub_keys[], int mode, uint64_t *result){
	if (mode == 1){
		for (int i = 0; i < blocks_len; i++){
			result[i] = encrypt_block(blocks[i], sub_keys);
		}
	}
}

uint64_t decrypt_block(uint64_t block, uint32_t sub_keys[]){
	uint32_t msg_hi = (uint32_t) (block >> 32);
        uint32_t *msg_hi_ptr = &msg_hi;
        uint32_t msg_lo = (uint32_t) ((block << 32) >> 32);
        uint32_t *msg_lo_ptr = &msg_lo;
        uint32_t *sub_key_ptr;
        for (int i = 0; i < 8; i++){
        	sub_key_ptr = &sub_keys[i];
		f_round(msg_hi_ptr, msg_lo_ptr, sub_key_ptr);
        }
        for (int i = 0; i < 24; i++){
		sub_key_ptr = &sub_keys[7 - (i % 8)];
		f_round(msg_hi_ptr, msg_lo_ptr, sub_key_ptr);
        }
        return ((uint64_t) msg_lo) << 32 | (uint64_t) msg_hi;
}

void main(){
	uint64_t x[10];
	for (int i = 0; i < 10; i++){
		getrandom(&x[i], sizeof(uint64_t), GRND_NONBLOCK);
	}
	uint32_t s[8];
	for (int i = 0; i < 8; i++){
		getrandom(&s[i], sizeof(uint32_t), GRND_NONBLOCK);
	}
	uint64_t enc[10];
	uint64_t *enc_ptr = enc;
	encrypt(x, 10, s, 1, enc_ptr);
	for (int i = 0; i < 10; i++){
		printf("%lu", enc[i]);
	}
}
