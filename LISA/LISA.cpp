
#include "pch.h"
#include "Lisa.h"

using namespace std;

int main()
{	
	Packet New;
	init_packet(&New);
	disp_packet(&New);

	srand(time(NULL));
	uint32_t offset = rand() % (BUFFER_SIZE - sizeof(Packet));
	init_global_buffer_wrap();

#if DEBUG
	printf("\n\nOffset = %x|%d,BUFFER @ %X, B+O = %X\n", offset, offset, (uint8_t*)buffer, (uint8_t*)buffer + offset);
#endif
	buff_pick((uint8_t*)buffer, BUFFER_SIZE);
	void* PacketPos = memcpy((uint8_t*)buffer + offset, &New, sizeof(Packet));
#if DEBUG
	display_buff((unsigned char*)buffer, BUFFER_SIZE);
#endif
	buff_dump((uint8_t*)buffer, BUFFER_SIZE);

	PacketPos = corrupt_frame_wrap(PacketPos);

	uint8_t* DetectPayload = detect_payload((uint8_t*)buffer,BUFFER_SIZE);
	display_buff((uint8_t*)DetectPayload,PAYLOAD_SIZE);


}

