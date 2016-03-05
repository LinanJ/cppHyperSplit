/*
 * global_def.h
 *
 *  Created on: 2015Äê9ÔÂ24ÈÕ
 *      Author: 10177270
 */

#ifndef GLOBAL_DEF_H_
#define GLOBAL_DEF_H_


/*************************** Macro Definition *********************/


/*************************** Profile *********************/
extern unsigned long long dff;
extern unsigned long c1;
extern unsigned long c2;
extern LARGE_INTEGER  large_interger;

#define PROFILE_START 		\
						do{\
							QueryPerformanceFrequency(&large_interger);\
							dff = large_interger.QuadPart;\
							QueryPerformanceCounter(&large_interger);\
							c1 = large_interger.QuadPart;\
						}while(0)


#define PROFILE_END 		\
						do{\
							QueryPerformanceCounter(&large_interger);\
							c2 = large_interger.QuadPart;\
							cout<<"Time Cost: "<<(unsigned long long)(c2 - c1)*1000 / dff<<" [ms]"<<endl;\
						}while(0)



#endif /* GLOBAL_DEF_H_ */
