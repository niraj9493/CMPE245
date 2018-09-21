/*
 * Lisa.h
 *
 *  Created on: Sep 19, 2018
 *      Author: Niraj93
 */


#ifndef LISA_H_
#define LISA_H_

#include <iostream>
#include <stdio.h>
#include <time.h>
#include<string.h>


using namespace std;

#define DEBUG 0

#define BUFFER_SIZE 256 	//2k bits = 256 Bytes
#define SYNC_SIZE 32
#define PAYLOAD_SIZE 16
#define FILENAME "mytestdata.txt"
#define CONFIDENCELVL 5
#define CORRUPT_PERCENT 50

void* buffer;

typedef struct
{
	uint8_t bytes[SYNC_SIZE];
}SyncField;

typedef struct
{
	SyncField syn;
	uint8_t Payload[PAYLOAD_SIZE];
}Packet;

/*
* Function Declarations
*/
void init_global_buffer_wrap();
uint8_t* corrupt_frame_wrap(void * PacketisHere);
void init_packet(Packet* P1);
uint8_t* detect_payload(uint8_t* buff, int size);
void disp_packet(Packet* P);
void fill_buffer(uint8_t* buff, int size);
void display_buff(unsigned char* buff, int size);
int no_of_one(uint8_t byte);
uint8_t gen_uniq_rand(int* Array, int size);
void* Corrupt_frame(void* PacketStart);
void* New_Corrupt_frame(void* PacketStart);
void buff_dump(uint8_t* buff, int size);
void buff_pick(uint8_t* buff, int size);
int lookup_sync(uint8_t);



/*
* Function Definitions
*/

void init_global_buffer_wrap()
{
	buffer = malloc(BUFFER_SIZE * sizeof(char));
	fill_buffer((uint8_t*)buffer, BUFFER_SIZE);
	display_buff((unsigned char*)buffer, BUFFER_SIZE);
	buff_dump((uint8_t*)buffer, BUFFER_SIZE);
}

uint8_t* corrupt_frame_wrap(void * PacketisHere)
{
	buff_pick((uint8_t*)buffer, BUFFER_SIZE);
	PacketisHere = New_Corrupt_frame(PacketisHere);
#if DEBUG
	display_buff((unsigned char*)buffer, BUFFER_SIZE);
#endif
	buff_dump((uint8_t*)buffer, BUFFER_SIZE);
	return (uint8_t*) PacketisHere;
}

void init_packet(Packet* P1)
{
	//Init SYNC
	for (int i = 0; i <= 0x0F; i++)
	{
		P1->syn.bytes[i] = (0xA0 + i);
		P1->syn.bytes[i + 0X0F + 1] = (0x50 + i);
	}

	//Init Payload
	for (int i = 0; i < PAYLOAD_SIZE; i++)
	{
		P1->Payload[i] = 0x9F;
	}
}

uint8_t* detect_payload(uint8_t* buff, int size)
{
	uint8_t mask[SYNC_SIZE];
	uint8_t CL_count = 0;
	bool found = false, firstbyte = false;
	uint8_t FirstBytePos = 0;
	void* at = NULL;

	//MASK INit
	for (int i = 0; i <= 0x0F; i++)
	{
		mask[i] = (0xA0 + i);
		mask[i + 0X0F + 1] = (0x50 + i);
	}

	//Pattern Matching
	uint8_t* ptr = (uint8_t*)buffer;
	for (int i = 0; i < BUFFER_SIZE; i++)
	{
		for (int j = 0; j < SYNC_SIZE; j++)
		{
			
#if DEBUG		
			printf("\nBUff: %02X, [J- %02X], [I+J - %02X @ %d]\n", ptr[i], mask[j], ptr[i + j], i + j);
#endif			
			
			if (mask[j] == ptr[j + i])
			{
				if (!firstbyte)
				{
					firstbyte = true;
					FirstBytePos = i + j;
				}
#if DEBUG		
				printf("\nHERE!\n M=%02X, Ptr=%02X\n", mask[j], ptr[j + i]);
#endif          
				CL_count++;
				if (CL_count >= CONFIDENCELVL)
					break;
			}
		}
		if (CL_count >= CONFIDENCELVL)
		{
			at = ptr + FirstBytePos;
			int some = (SYNC_SIZE - lookup_sync(*(ptr + FirstBytePos)));
			at = (uint8_t*)at + some;
			found = true;
			break;
		}
		else
		{
			firstbyte = false;
			CL_count = 0;
		}
	}
	return (uint8_t*)at;
}


void disp_packet(Packet* P)
{
	printf("------Displaying Packet------\n");
	printf("Sync Field:\n");
	for (int i = 0; i < 32; i++)
	{
		if (i % 8 == 0)
		{
			printf("\n");
		}
		printf("%02X ", P->syn.bytes[i]);
	}

	printf("\n\nPayload:\n");
	for (int i = 0; i < PAYLOAD_SIZE; i++)
	{
		if (i % 8 == 0)
		{
			printf("\n");
		}
		printf("%02X ", P->Payload[i]);
	}
	printf("\n\n-----END OF PACKET-----\n");
	fflush(stdout);
}

void display_buff(unsigned char* buff, int size)
{
	printf("\n\n=========== BUFFER ===========\n");
	for (int i = 0; i < size; i++)
	{
		if (i % 10 == 0)
		{
			printf("\n%02d--->", i / 10);
		}
		printf("%02X ", buff[i]);
	}
	fflush(stdout);
}

void buff_dump(uint8_t* buff, int size)
{
	FILE *fd = fopen(FILENAME, "w");
	for (int i = 0; i < size; i++)
	{
		if (i % 10 == 0 && i != 0)
		{
			fprintf(fd, "\n");
		}
		fprintf(fd, "%02X ", buff[i]);
	}
	fclose(fd);
}
void buff_pick(uint8_t* buff, int size)
{
	uint8_t byte=0x00;
	void* ptr = malloc(size * sizeof(uint8_t));
	uint8_t* it = (uint8_t*)ptr;
	int sizeloop = size;
	FILE *fd = fopen(FILENAME, "r");
	
	while ((fscanf(fd, "%02X", &byte) == 1) && sizeloop >0)
	{
		//printf("%02X ", byte);
		*it = byte;
		it++;
		sizeloop--;
	}
	memcpy(buff, ptr, size);
	//display_buff((uint8_t*)buff, size);
	fclose(fd);
}

int no_of_one(uint8_t byte)
{
	uint8_t ones[] = { 0,1,1,2,
		1,2,2,3,
		1,2,2,3,
		2,3,3,4
	};

	uint8_t UN = 0, LN = 0;
	UN = (byte >> 4) & 0x0F;
	LN = byte & 0x0F;
	return (ones[UN] + ones[LN]);
}

int lookup_sync(uint8_t Index)
{
	if (((Index >> 4) & 0x0F) == (0x0A))
	{
		return(Index & 0x0F);
	}
	else if (((Index >> 4) & 0x0F) == (0x05))
	{
		return((Index & 0x0F) + 0x10);
	}
	else
	{
		return 0;
	}
}

uint8_t gen_uniq_rand(int* Array, int size)
{
	bool check;
	uint8_t num;
	do
	{
		check = true;
		num = rand() % size;
		for (int i = 0; i < size; i++)
		{
			if (Array[i] == num)
			{
				check = false;
				break;
			}
		}
	} while (!check);

#if DEBUG
	printf("\nUnique Generated: %02X\n", num);
#endif

	Array[num] = num;
	return num;
}

void* New_Corrupt_frame(void* PacketStart)
{

	int Totalbits = SYNC_SIZE * 8;
	int BitsToChange = (Totalbits*CORRUPT_PERCENT / 100);
#if DEBUG
	printf("\n\nBits to Corrupt: %d\n", BitsToChange);
#endif
	int loop = BitsToChange;
	int RNGArray[SYNC_SIZE] = { 0x99 };
	while (loop > 0)
	{
		uint32_t RandAccess = gen_uniq_rand(RNGArray, SYNC_SIZE); //Generate Unique Random No. between 0 to 31
#if DEBUG
		for (int i = 0; i < SYNC_SIZE; i++)
			printf("%02X ", RNGArray[i]);
		printf("\n");
		fflush(stdout);
#endif
		uint8_t byte;
		memcpy(&byte, (uint8_t*)PacketStart + RandAccess, sizeof(byte));
#if DEBUG
		printf("Byte: %02X,", byte);
#endif
		if (loop <= 8)
		{
			uint8_t x = 0;
			uint8_t Bits_to_Toggle = loop;
			while (Bits_to_Toggle > 0)
			{
				x = x << 1;
				x |= (1 << 1);
				Bits_to_Toggle--;
			}
			byte = x + rand();
			loop = 0;
		}
		else
		{
			byte = (byte << 4) | (byte >> 4);
			byte++;
			byte = ~byte;
			loop -= 8;
		}
#if DEBUG
		printf("to : %02X,", byte);
#endif
		memcpy((uint8_t*)PacketStart + RandAccess, &byte, sizeof(byte));

#if DEBUG
		printf("Bits Remain: %d\n", loop);
		printf("\n-----------------------------------------------------\n");
		fflush(stdout);
#endif

	}
	return PacketStart;
}

void* Corrupt_frame(void* PacketStart)
{
	int Totalbits = SYNC_SIZE * 8;
	int BitsToChange = (Totalbits*CORRUPT_PERCENT / 100);
#if DEBUG
	printf("\n\nBits to Corrupt: %d\n", BitsToChange);
#endif
	int loop = BitsToChange;
	int RNGArray[SYNC_SIZE] = { 0 };

	while (loop > 0)
	{
		uint32_t RandAccess = gen_uniq_rand(RNGArray, SYNC_SIZE); //Generate Unique Random No. between 0 to 31
#if DEBUG
		for (int i = 0; i < SYNC_SIZE; i++)
			printf("%02X ", RNGArray[i]);
		printf("\n");
		fflush(stdout);

#endif
		uint8_t byte;
		memcpy(&byte, (uint8_t*)PacketStart + RandAccess, sizeof(byte));
#if DEBUG
		printf("%02X , RAND:", byte);
		fflush(stdout);
#endif

		uint8_t randbyte = rand();
#if DEBUG
		printf("%02X, ", randbyte);
		fflush(stdout);
#endif

		memcpy((uint8_t*)PacketStart + RandAccess, &randbyte, sizeof(randbyte));
		loop -= no_of_one(randbyte ^ byte);
#if DEBUG
		printf("Bits Remain: %d\n", loop);
		printf("\n-----------------------------------------------------\n");
		fflush(stdout);
#endif

	}
	return PacketStart;
}

void fill_buffer(uint8_t* buff, int size)
{
	for (int i = 0; i < size; i++)
	{
		uint8_t byte = rand();
		*(buff + i) = byte;
	}
}





#endif /* LISA_H_ */

