
#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <time.h>
#include<string.h>
#include "Lisa.h"

using namespace std;

int main()
{	
	Packet New;
	init_packet(&New);
	disp_packet(&New);

	srand(time(NULL));
	uint32_t offset = rand() % (BUFFER_SIZE - sizeof(Packet));
	buffer = malloc(BUFFER_SIZE * sizeof(char));
	fill_buffer((uint8_t*)buffer, BUFFER_SIZE);
	display_buff((unsigned char*)buffer, BUFFER_SIZE);
	buff_dump((uint8_t*)buffer, BUFFER_SIZE);

#if DEBUG
	printf("\n\nOffset = %x|%d,BUFFER @ %X, B+O = %X\n", offset, offset, (uint8_t*)buffer, (uint8_t*)buffer + offset);
#endif
	buff_pick((uint8_t*)buffer, BUFFER_SIZE);
	void* PacketPos = memcpy((uint8_t*)buffer + offset, &New, sizeof(Packet));

	display_buff((unsigned char*)buffer, BUFFER_SIZE);
	buff_dump((uint8_t*)buffer, BUFFER_SIZE);

	PacketPos = New_Corrupt_frame(PacketPos);

	display_buff((unsigned char*)buffer, BUFFER_SIZE);
	buff_dump((uint8_t*)buffer, BUFFER_SIZE);

		uint8_t mask[SYNC_SIZE];
	    uint8_t CL_count = 0;
	    bool found = false,firstbyte=false;
		uint8_t FirstBytePos = 0;
	    void* at=NULL;
	    for (int i = 0; i <= 0x0F; i++)
	    {
	        mask[i] = (0xA0 + i);
	        mask[i + 0X0F + 1] = (0x50 + i);
	    }
	    uint8_t* ptr = (uint8_t*)buffer;
	    for (int i = 0; i<BUFFER_SIZE; i++)
	    {
	        
			for (int j = 0; j<SYNC_SIZE; j++)
	        {	
				printf("\nBUff: %02X, [J- %02X], [I+J - %02X @ %d]\n", ptr[i], mask[j], ptr[i + j],i+j);
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
	            }
	        }
	        if (CL_count >= CONFIDENCELVL)
	        {
				at = ptr + FirstBytePos;
				int some = (SYNC_SIZE - lookup_sync(*(ptr + FirstBytePos)));
				at = (uint8_t*)at +some;
				found = true;
	            break;
	        }
	        else
	        {	
				firstbyte = false;
	            CL_count = 0;
	        }
	    }
		display_buff((uint8_t*)at,PAYLOAD_SIZE);


}

