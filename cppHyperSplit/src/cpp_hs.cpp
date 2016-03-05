/*
 * cpp_hs.cpp
 *
 *  Created on: 2015Äê10ÔÂ30ÈÕ
 *      Author: 10177270
 */

//#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <memory.h>
#include <windows.h>
#include <string.h>
#include <vector>
#include <iterator>
#include "GlobalVer.h"
#include "GlobalDef.h"
#include "cpp_hs.h"

using namespace std;

/*-----------------------------------------------------------------------------
 *  globals
 *-----------------------------------------------------------------------------*/
unsigned int gNumInterNode = 0;
unsigned int gNumLeafNode = 0;

unsigned int gWstDepth = 0;
unsigned int gAvgDepth = 0;

unsigned int gNumNonOverlappings[DIM];
unsigned long long gNumTotalNonOverlappings = 1;

//struct timeval	gStartTime,gEndTime;

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  ReadIPRange
 *  Description:
 * =====================================================================================
 */
void ReadIPRange(FILE* fp, unsigned int* IPrange) {
	/*asindmemacces IPv4 prefixes*/
	/*temporary variables to store IP range */
	unsigned int trange[4];
	unsigned int mask;
	char validslash;
	int masklit1;
	unsigned int masklit2, masklit3;
	unsigned int ptrange[4];
	int i;
	/*read IP range described by IP/mask*/
	/*fscanf(fp, "%d.%d.%d.%d/%d", &trange[0],&trange[1],&trange[2],&trange[3],&mask);*/
	if (4
			!= fscanf(fp, "%d.%d.%d.%d", &trange[0], &trange[1], &trange[2],
					&trange[3])) {
		printf("\n>> [err] ill-format IP rule-file\n");
		exit(-1);
	}
	if (1 != fscanf(fp, "%c", &validslash)) {
		printf("\n>> [err] ill-format IP slash rule-file\n");
		exit(-1);
	}
	/*deal with default mask*/
	if (validslash != '/')
		mask = 32;
	else {
		if (1 != fscanf(fp, "%d", &mask)) {
			printf("\n>> [err] ill-format mask rule-file\n");
			exit(-1);
		}
	}
	mask = 32 - mask;
	masklit1 = mask / 8;
	masklit2 = mask % 8;

	for (i = 0; i < 4; i++)
		ptrange[i] = trange[i];

	/*count the start IP */
	for (i = 3; i > 3 - masklit1; i--)
		ptrange[i] = 0;
	if (masklit2 != 0) {
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		masklit3 = ~masklit3;
		ptrange[3 - masklit1] &= masklit3;
	}
	/*store start IP */
	IPrange[0] = ptrange[0];
	IPrange[0] <<= 8;
	IPrange[0] += ptrange[1];
	IPrange[0] <<= 8;
	IPrange[0] += ptrange[2];
	IPrange[0] <<= 8;
	IPrange[0] += ptrange[3];

	/*count the end IP*/
	for (i = 3; i > 3 - masklit1; i--)
		ptrange[i] = 255;
	if (masklit2 != 0) {
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		ptrange[3 - masklit1] |= masklit3;
	}
	/*store end IP*/
	IPrange[1] = ptrange[0];
	IPrange[1] <<= 8;
	IPrange[1] += ptrange[1];
	IPrange[1] <<= 8;
	IPrange[1] += ptrange[2];
	IPrange[1] <<= 8;
	IPrange[1] += ptrange[3];
}

void ReadPort(FILE* fp, unsigned int* from, unsigned int* to) {
	unsigned int tfrom;
	unsigned int tto;
	if (2 != fscanf(fp, "%d : %d", &tfrom, &tto)) {
		printf("\n>> [err] ill-format port range rule-file\n");
		exit(-1);
	}
	*from = tfrom;
	*to = tto;
}

void ReadProtocol(FILE* fp, unsigned int* from, unsigned int* to) {
	//TODO: currently, only support single protocol, or wildcard
	char dump = 0;
	unsigned int proto = 0, len = 0;
	if (7
			!= fscanf(fp, " %c%c%x%c%c%c%x", &dump, &dump, &proto, &dump, &dump,
					&dump, &len)) {
		printf("\n>> [err] ill-format protocol rule-file\n");
		exit(-1);
	}
	if (len == 0xff) {
		*from = proto;
		*to = *from;
	} else {
		*from = 0x0;
		*to = 0xff;
	}
}

int ReadFilter(FILE* fp, struct FILTSET* filtset, unsigned int cost) {
	/*allocate a few more bytes just to be on the safe side to avoid overflow etc*/
	char validfilter; /* validfilter means an '@'*/
	struct FILTER *tempfilt, tempfilt1;

	while (!feof(fp)) {

		if (0 != fscanf(fp, "%c", &validfilter)) {
			/*printf ("\n>> [err] ill-format @ rule-file\n");*/
			/*exit (-1);*/
		}
		if (validfilter != '@')
			continue; /* each rule should begin with an '@' */

		tempfilt = &tempfilt1;
		ReadIPRange(fp, tempfilt->dim[0]); /* reading SIP range */
		ReadIPRange(fp, tempfilt->dim[1]); /* reading DIP range */

		ReadPort(fp, &(tempfilt->dim[2][0]), &(tempfilt->dim[2][1]));
		ReadPort(fp, &(tempfilt->dim[3][0]), &(tempfilt->dim[3][1]));

		ReadProtocol(fp, &(tempfilt->dim[4][0]), &(tempfilt->dim[4][1]));

		/*read action taken by this rule
		 fscanf(fp, "%d", &tact);
		 tempfilt->act = (unsigned char) tact;

		 read the cost (position) , which is specified by the last parameter of this function*/
		tempfilt->cost = cost;

		// copy the temp filter to the global one
		memcpy(&(filtset->filtArr[filtset->numFilters]), tempfilt,
				sizeof(struct FILTER));

		filtset->numFilters++;
		return SUCCESS;
	}
	return FALSE;
}

void LoadFilters(FILE *fp, struct FILTSET *filtset) {
	int line = 0;
	filtset->numFilters = 0;
	while (!feof(fp)) {
		ReadFilter(fp, filtset, line);
		line++;
	}
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:	ReadFilterFile
 *  Description:	Read rules from file.
 *					Rules are stored in 'filterset' for range matching
 * =====================================================================================
 */
int ReadFilterFile() {
	unsigned int i, j;
	FILE* fp;
	struct RULE_SET* ruleset;
	ruleset = &gRuleset;

//	char filename[10] = "acl.txt";	/* filter file name */
	fp = fopen(FILTER_FILE, "r");
	if (fp == NULL) {
		printf("Couldnt open filter set file \n");
		return FAILURE;
	}

	LoadFilters(fp, &filtset);
	fclose(fp);

	/*
	 *copy rules to dynamic structrue, and from now on, everything is new:-)
	 */
	ruleset->num = filtset.numFilters;
	ruleset->ruleList = (struct RULE*) malloc(
			ruleset->num * sizeof(struct RULE));
	if (ruleset->ruleList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += ruleset->num * sizeof(struct RULE);
		gStatistic.currMalloc += ruleset->num * sizeof(struct RULE);
	}
	for (i = 0; i < ruleset->num; i++) {
		ruleset->ruleList[i].pri = filtset.filtArr[i].cost;
		for (j = 0; j < DIM; j++) {
			ruleset->ruleList[i].range[j][0] = filtset.filtArr[i].dim[j][0];
			ruleset->ruleList[i].range[j][1] = filtset.filtArr[i].dim[j][1];
		}
	}
	/*printf("\n>>number of rules loaded from file: %d", ruleset->num);*/

	return SUCCESS;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Compare
 *  Description:  for qsort
 *     Comments:  who can make it better?
 * =====================================================================================
 */
int SegPointCompare(const void * a, const void * b) {
	if (*(unsigned int*) a < *(unsigned int*) b)
		return -1;
	else if (*(unsigned int*) a == *(unsigned int*) b)
		return 0;
	else
		return 1;
}

int InitRootNode(struct HS_NODE* pNode) {
	/*
	 unsigned char		depth;			set
	 struct RULE_SET* 	ruleset;		set
	 unsigned int		NodeRange[2];	set
	 */

	pNode->depth = 0;
//	for(unsigned int dim=0; dim<DIM;dim++){
//
//		pNode->NodeRange[dim][0]=0;
//		pNode->NodeRange[dim][1]=0xFFFFFFFF;
//	}
	pNode->d2s = 0xFF;
	pNode->thresh = 0xFFFFFFFF;
	pNode->child[0] = NULL;
	pNode->child[1] = NULL;

	pNode->ruleset = (struct RULE_SET*) malloc(sizeof(struct RULE_SET));
	if (pNode->ruleset == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += sizeof(struct RULE_SET);
		gStatistic.currMalloc += sizeof(struct RULE_SET);
	}
	pNode->ruleset->num = gRuleset.num;
	pNode->ruleset->ruleList = (struct RULE*) malloc(
			gRuleset.num * sizeof(struct RULE));
	if (pNode->ruleset->ruleList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += gRuleset.num * sizeof(struct RULE);
		gStatistic.currMalloc += gRuleset.num * sizeof(struct RULE);
	}
	memcpy(pNode->ruleset->ruleList, gRuleset.ruleList,
			gRuleset.num * sizeof(struct RULE));

	return SUCCESS;
}

int GenPairSubNode(struct HS_NODE* currNode) {
	/*
	 *
	 * currNode:::
	 * unsigned char		d2s;			set
	 unsigned char		depth;			get
	 unsigned int		thresh;			set
	 struct HS_NODE*	child[2];			set
	 struct RULE_SET* 	ruleset;		get
	 unsigned int		NodeRange[2];	get

	 */

#ifndef FULLHS
	/* found leaf node
	 * set currNode
	 * */
	if (currNode->ruleset->num <= HSINC) {
		currNode->d2s = 0x0;
		currNode->thresh = 0x0;
//			currNode->depth++;
//			currNode->ruleset reserved
		currNode->child[0] = NULL;
		currNode->child[1] = NULL;

		/* must be Merged depend on priority*/
		//			currNode->ruleset->num=1;
		gLeafset.push_back(currNode);

		gNumLeafNode++;

		if (gWstDepth < currNode->depth)
			gWstDepth = currNode->depth;
		gAvgDepth += currNode->depth;

		return SUCCESS;
	}
#endif

	/* generate segments for input filtset */
	unsigned int dim, num, pos;

	/* maximum different segment points */
	unsigned int maxDiffSegPts = 1;

	/* dimension to split (with max diffseg) */
	unsigned int d2s = 0;
	unsigned int thresh;

	/* sub-space ranges for child-nodes */
	unsigned int sub_range[2][2];
	unsigned int *segPoints[DIM];
	unsigned int *segPointsInfo[DIM];
	unsigned int *tempSegPoints;
	unsigned int *tempRuleNumList;
	float hightAvg, hightAll;

	/*************************** Projecting *******************************/

	/*Generate Segment Points from Rules*/
	for (dim = 0; dim < DIM; dim++) {
		/* N rules have 2*N segPoints */
		segPoints[dim] = (unsigned int*) malloc(
				2 * currNode->ruleset->num * sizeof(unsigned int));
		if (segPoints[dim] == NULL) {
			printf("malloc fail...");
			exit(0);
		} else {
			gStatistic.MaxMalloc += 2 * currNode->ruleset->num
					* sizeof(unsigned int);
			gStatistic.currMalloc += 2 * currNode->ruleset->num
					* sizeof(unsigned int);
		}

		segPointsInfo[dim] = (unsigned int*) malloc(
				2 * currNode->ruleset->num * sizeof(unsigned int));
		if (segPointsInfo[dim] == NULL) {
			printf("malloc fail...");
			exit(0);
		} else {
			gStatistic.MaxMalloc += 2 * currNode->ruleset->num
					* sizeof(unsigned int);
			gStatistic.currMalloc += 2 * currNode->ruleset->num
					* sizeof(unsigned int);
		}

		for (num = 0; num < currNode->ruleset->num; num++) {
			segPoints[dim][2 * num] =
					currNode->ruleset->ruleList[num].range[dim][0];
			segPoints[dim][2 * num + 1] =
					currNode->ruleset->ruleList[num].range[dim][1];
		}
	}

	/*Sort the Segment Points*/
	for (dim = 0; dim < DIM; dim++) {
		/*void qsort(void*base,size_t num,size_t width,int(__cdecl*compare)(const void*,const void*));
		 */
		qsort(segPoints[dim], 2 * currNode->ruleset->num, sizeof(unsigned int),
				SegPointCompare);
	}

	/*Compress the Segment Points, and select the dimension to split (d2s)*/
	tempSegPoints = (unsigned int*) malloc(
			2 * currNode->ruleset->num * sizeof(unsigned int));
	if (tempSegPoints == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += 2 * currNode->ruleset->num
				* sizeof(unsigned int);
		gStatistic.currMalloc += 2 * currNode->ruleset->num
				* sizeof(unsigned int);
	}

	hightAvg = 2 * currNode->ruleset->num + 1;
	for (dim = 0; dim < DIM; dim++) {
		unsigned int i, j;
		unsigned int *hightList;
		unsigned int diffSegPts = 1; /* at least there are one differnt segment point */
		tempSegPoints[0] = segPoints[dim][0];

		/*de Duplicate*/
		for (num = 1; num < 2 * currNode->ruleset->num; num++) {
			if (segPoints[dim][num] != tempSegPoints[diffSegPts - 1]) {
				tempSegPoints[diffSegPts] = segPoints[dim][num];
				diffSegPts++;
			}
		}

		/* Until now, rules projected to field in segPoints[DIM],
		 * diffSegPts is the number of points which is different with each other in sort */

		/*Span the segment points which is both start and end of some rules*/
		pos = 0;
		for (num = 0; num < diffSegPts; num++) {
			unsigned int i;
			int ifStart = 0;
			int ifEnd = 0;
			segPoints[dim][pos] = tempSegPoints[num];

			/*trance rule-set to find out diffSegPts is either start or end*/
			for (i = 0; i < currNode->ruleset->num; i++) {
				if (currNode->ruleset->ruleList[i].range[dim][0]
						== tempSegPoints[num]) {
					/*printf ("\n>>rule[%d] range[0]=%x", i, ruleset->ruleList[i].range[dim][0]);*/
					/*this segment point is a start point*/
					ifStart = 1;
					break;
				}
			}
			for (i = 0; i < currNode->ruleset->num; i++) {
				if (currNode->ruleset->ruleList[i].range[dim][1]
						== tempSegPoints[num]) {
					/*printf ("\n>>rule[%d] range[1]=%x", i, ruleset->ruleList[i].range[dim][1]);*/
					/* this segment point is an end point */
					ifEnd = 1;
					break;
				}
			}

			/*
			 * segPointsInfo==0 : start
			 * segPointsInfo==1 : end
			 * */

			if (ifStart && ifEnd) {
				segPointsInfo[dim][pos] = 0;
				pos++;
				segPoints[dim][pos] = tempSegPoints[num];

				/*skip*/
				segPointsInfo[dim][pos] = 1;
				pos++;
			} else if (ifStart) {
				segPointsInfo[dim][pos] = 0;
				pos++;
			} else {
				segPointsInfo[dim][pos] = 1;
				pos++;
			}

		}/*ending project in this dim*/

		/*
		 * Calc hightList & hightAll
		 * hightList is weight for every single seg
		 * hightAll is all weight
		 *
		 * */
		if (pos >= 3) {
			hightAll = 0;
			hightList = (unsigned int *) malloc(pos * sizeof(unsigned int));
			if (hightList == NULL) {
				printf("malloc fail...");
				exit(0);
			} else {
				gStatistic.MaxMalloc += pos * sizeof(unsigned int);
				gStatistic.currMalloc += pos * sizeof(unsigned int);
			}

			for (i = 0; i < pos - 1; i++) {
				hightList[i] = 0;

				/*trace rule-set to find hightList & hightAll*/
				for (j = 0; j < currNode->ruleset->num; j++) {
					if (currNode->ruleset->ruleList[j].range[dim][0]
							<= segPoints[dim][i]
							&& currNode->ruleset->ruleList[j].range[dim][1]
									>= segPoints[dim][i + 1]) {
						hightList[i]++;
						hightAll++;
					}
				}
			}

			/*
			 * d2s is the dimension to split
			 * pos-1 is the number of segs
			 * thresh is the split point
			 * */
			if (hightAvg > hightAll / (pos - 1)) {
				float hightSum = 0;

				/* select current dimension */
				d2s = dim;
				hightAvg = hightAll / (pos - 1);

				/* the first segment MUST belong to the leff child */
				hightSum += hightList[0];
				for (num = 1; num < pos - 1; num++) { /* pos-1 >= 2; seg# = num */
					if (segPointsInfo[d2s][num] == 0)
						thresh = segPoints[d2s][num] - 1;
					else
						thresh = segPoints[d2s][num];

					if (hightSum > hightAll / 2) {
						break;
					}
					hightSum += hightList[num];
				}

				/*printf("\n>>d2s=%u thresh=%x\n", d2s, thresh);*/
				/*generating the sub range */
				sub_range[0][0] = segPoints[d2s][0];
				sub_range[0][1] = thresh;
				sub_range[1][0] = thresh + 1;
				sub_range[1][1] = segPoints[d2s][pos - 1];
			}

			free(hightList);
			hightList = NULL;

		} /* if pos >=3 */

		if (maxDiffSegPts < pos) {
			maxDiffSegPts = pos;
		}
	}/*ending selected field to split*/

	free(tempSegPoints);
	tempSegPoints = NULL;
	for (dim = 0; dim < DIM; dim++) {
		free(segPoints[dim]);
		segPoints[dim] = NULL;
		free(segPointsInfo[dim]);
		segPointsInfo[dim] = NULL;
	}

	/* found leaf node*/
	/*set currNode*/
	if (maxDiffSegPts <= 2) {
		currNode->d2s = 0x0;
//		currNode->depth++;
		currNode->thresh = 0x0;
		currNode->child[0] = NULL;
		currNode->child[1] = NULL;

		/* must be Merged depend on priority*/
		currNode->ruleset->num = 1;

		gLeafset.push_back(currNode);

		gNumLeafNode++;

		if (gWstDepth < currNode->depth)
			gWstDepth = currNode->depth;
		gAvgDepth += currNode->depth;

		return SUCCESS;
	}

	/*Update Inter Node, Binary split along d2s*/
	if (sub_range[1][0] > sub_range[1][1]) {
		printf("\n>>maxDiffSegPts=%d  range[1][0]=%x  range[1][1]=%x",
				maxDiffSegPts, sub_range[1][0], sub_range[1][1]);
		printf("\n>>error\n");
		exit(0);
	}

	/*Update Inter Node Structure*/
	/*	set currNode*/
	gNumInterNode++;
	currNode->d2s = (unsigned char) d2s;
	currNode->thresh = thresh;
//	currNode->depth = (unsigned char) depth;

	/***************** forming hs sub node **********************/
	/*Generate left child rule list*/
	/*set  child[0] as lefe HS-NODE*/
	currNode->child[0] = (struct HS_NODE *) malloc(sizeof(struct HS_NODE));
	if (currNode->child[0] == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += sizeof(struct HS_NODE);
		gStatistic.currMalloc += sizeof(struct HS_NODE);
	}

	tempRuleNumList = (unsigned int*) malloc(
			currNode->ruleset->num * sizeof(unsigned int)); /* need to be freed */
	if (tempRuleNumList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += currNode->ruleset->num * sizeof(unsigned int);
		gStatistic.currMalloc += currNode->ruleset->num * sizeof(unsigned int);
	}

	pos = 0;
	for (num = 0; num < currNode->ruleset->num; num++) {
		if (currNode->ruleset->ruleList[num].range[d2s][0] <= sub_range[0][1]
				&& currNode->ruleset->ruleList[num].range[d2s][1]
						>= sub_range[0][0]) {
			tempRuleNumList[pos] = num;
			pos++;
		}
	}

	/* it can be improved here
	 * read index in gRuleSet, not in ruleset
	 * storing index of rule, unsigned short [num]
	 * */

	currNode->child[0]->ruleset = (struct RULE_SET*) malloc(
			sizeof(struct RULE_SET));
	if (currNode->child[0]->ruleset == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += sizeof(struct RULE_SET);
		gStatistic.currMalloc += sizeof(struct RULE_SET);
	}

	currNode->child[0]->ruleset->num = pos;
	currNode->child[0]->ruleset->ruleList = (struct RULE*) malloc(
			currNode->child[0]->ruleset->num * sizeof(struct RULE));
	if (currNode->child[0]->ruleset->ruleList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += currNode->child[0]->ruleset->num
				* sizeof(struct RULE);
		gStatistic.currMalloc += currNode->child[0]->ruleset->num
				* sizeof(struct RULE);
	}

	for (num = 0; num < currNode->child[0]->ruleset->num; num++) {
		currNode->child[0]->ruleset->ruleList[num] =
				currNode->ruleset->ruleList[tempRuleNumList[num]];
		/* in d2s dim, the search space needs to be trimmed off */
		if (currNode->child[0]->ruleset->ruleList[num].range[d2s][0]
				< sub_range[0][0])
			currNode->child[0]->ruleset->ruleList[num].range[d2s][0] =
					sub_range[0][0];
		if (currNode->child[0]->ruleset->ruleList[num].range[d2s][1]
				> sub_range[0][1])
			currNode->child[0]->ruleset->ruleList[num].range[d2s][1] =
					sub_range[0][1];
	}
	free(tempRuleNumList);
	tempRuleNumList = NULL;

	/*set lefe HS-NODE*/
	currNode->child[0]->d2s = 0xFF;
	currNode->child[0]->thresh = 0xFFFFFFFF;
	currNode->child[0]->depth = currNode->depth + 1;
	currNode->child[0]->child[0] = NULL;
	currNode->child[0]->child[1] = NULL;
//	currNode->child[0]->NodeRange[d2s][0]=sub_range[0][0];
//	currNode->child[0]->NodeRange[d2s][1]=sub_range[0][1];

	/*left side iterating ...*/
//	GenPairSubNode(childRuleSet, currNode->child[0], depth + 1);

	/*Generate right child rule list*/
	/*set  child[0] as lefe HS-NODE*/

	currNode->child[1] = (struct HS_NODE *) malloc(sizeof(struct HS_NODE));
	if (currNode->child[1] == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += sizeof(struct HS_NODE);
		gStatistic.currMalloc += sizeof(struct HS_NODE);
	}

	tempRuleNumList = (unsigned int*) malloc(
			currNode->ruleset->num * sizeof(unsigned int)); /* need to be free */
	if (tempRuleNumList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += currNode->ruleset->num * sizeof(unsigned int);
		gStatistic.currMalloc += currNode->ruleset->num * sizeof(unsigned int);
	}

	pos = 0;
	for (num = 0; num < currNode->ruleset->num; num++) {
		if (currNode->ruleset->ruleList[num].range[d2s][0] <= sub_range[1][1]
				&& currNode->ruleset->ruleList[num].range[d2s][1]
						>= sub_range[1][0]) {
			tempRuleNumList[pos] = num;
			pos++;
		}
	}

	currNode->child[1]->ruleset = (struct RULE_SET*) malloc(
			sizeof(struct RULE_SET));
	if (currNode->child[1]->ruleset == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += sizeof(struct RULE_SET);
		gStatistic.currMalloc += sizeof(struct RULE_SET);
	}

	currNode->child[1]->ruleset->num = pos;
	currNode->child[1]->ruleset->ruleList = (struct RULE*) malloc(
			currNode->child[1]->ruleset->num * sizeof(struct RULE));
	if (currNode->child[1]->ruleset->ruleList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += currNode->child[1]->ruleset->num
				* sizeof(struct RULE);
		gStatistic.currMalloc += currNode->child[1]->ruleset->num
				* sizeof(struct RULE);
	}

	for (num = 0; num < currNode->child[1]->ruleset->num; num++) {
		currNode->child[1]->ruleset->ruleList[num] =
				currNode->ruleset->ruleList[tempRuleNumList[num]];
		/* in d2s dim, the search space needs to be trimmed off */
		if (currNode->child[1]->ruleset->ruleList[num].range[d2s][0]
				< sub_range[1][0])
			currNode->child[1]->ruleset->ruleList[num].range[d2s][0] =
					sub_range[1][0];
		if (currNode->child[1]->ruleset->ruleList[num].range[d2s][1]
				> sub_range[1][1])
			currNode->child[1]->ruleset->ruleList[num].range[d2s][1] =
					sub_range[1][1];
	}

	free(tempRuleNumList);
	tempRuleNumList = NULL;

	/*right side iterating ...*/
//	GenPairSubNode(LeftSubRuleSet, currNode->child[1], depth + 1);
	/*set right HS-NODE*/
	currNode->child[1]->d2s = 0xF;
	currNode->child[1]->thresh = 0xFFFFFFFF;
	currNode->child[1]->depth = currNode->depth + 1;
	currNode->child[1]->child[0] = NULL;
	currNode->child[1]->child[1] = NULL;
//	currNode->child[1]->NodeRange[d2s][0]=sub_range[1][0];
//	currNode->child[1]->NodeRange[d2s][1]=sub_range[1][1];

	/*	free rule set of currNode */
	free(currNode->ruleset->ruleList);
	currNode->ruleset->ruleList = NULL;
	free(currNode->ruleset);
	currNode->ruleset = NULL;

	return SUCCESS;
}

int BuildHSTree(struct HS_NODE* pCurrNode) {

	int iRet = SUCCESS;

	if (pCurrNode == NULL) {
		printf("pRoot==NULL");
		exit(1);
	}

	while (pCurrNode != NULL) {

		iRet = GenPairSubNode(pCurrNode);

		if (pCurrNode->child[1] != NULL) {
//			free(pCurrNode->ruleset);
			gNodeStack.push_back(pCurrNode->child[1]);
		}

		if (pCurrNode->child[0] != NULL) {
//			free(pCurrNode->ruleset);
			pCurrNode = pCurrNode->child[0];
		} else {
			if (gNodeStack.empty()) {
				break;
			}
			pCurrNode = gNodeStack.back();
			gNodeStack.pop_back();
		}

	}

	return SUCCESS;
}

int GetIpset() {
	gIpset.num = gRuleset.num;

	gIpset.ipList = (struct IP*) malloc(gIpset.num * sizeof(struct IP));
	if (gIpset.ipList == NULL) {
		printf("malloc fail...");
		exit(0);
	} else {
		gStatistic.MaxMalloc += gIpset.num * sizeof(struct IP);
		gStatistic.currMalloc += gIpset.num * sizeof(struct IP);
	}

	for (unsigned int i = 0; i < gIpset.num; i++) {
		for (unsigned int dim = 0; dim < DIM; dim++) {
			gIpset.ipList[i].ip[dim] = gRuleset.ruleList[i].range[dim][0];
		}
	}

	printf("generated ip set !!!");
	return SUCCESS;
}





unsigned int PickRuleinLeaf(struct IP* ptmpIP, struct HS_NODE* ptmpNode) {

	if(ptmpNode->ruleset==NULL){
		printf("it is not leaf !!! \n");
		exit(0);
	}

	unsigned int tmpRuleStart;
	unsigned int tmpRuleEnd;
	for(unsigned int indx=0; indx<ptmpNode->ruleset->num;indx++){
		for(unsigned int dim=0; dim<DIM;dim++){

			tmpRuleStart=ptmpNode->ruleset->ruleList[indx].range[dim][0];
			tmpRuleEnd=ptmpNode->ruleset->ruleList[indx].range[dim][1];

			if(ptmpIP->ip[dim]< tmpRuleStart || ptmpIP->ip[dim] > tmpRuleEnd){
				goto SEARCHNEXT;
			}
		}
		return ptmpNode->ruleset->ruleList[indx].pri;

		SEARCHNEXT: ;
	}

	printf("there is no match rule!!!");
	return 0xFFFFFFFF;
}



int LookUpinHSTree(struct IPSET* ptmpIPset) {
	//TODO:
	struct HS_NODE* ptmpNode;
	unsigned int tmpIndx;

	for (unsigned int i = 0; i < ptmpIPset->num; i++) {
		//searched once
		ptmpNode = &gRootnode;

		while (ptmpNode->child[0] != NULL) {
			if (ptmpIPset->ipList[i].ip[ptmpNode->d2s] <= ptmpNode->thresh)
				ptmpNode = ptmpNode->child[0];
			else
				ptmpNode = ptmpNode->child[1];
		}

		gLookupLeaf.push_back(ptmpNode->ruleset);
		tmpIndx=PickRuleinLeaf(&(ptmpIPset->ipList[i]),ptmpNode);
		gLookupIndx.push_back(tmpIndx);
	}

	return SUCCESS;
}


int WrittenLookResults() {


	/*	writting searched leaf*/
	FILE *fp;

	char filename1[] = "LookupLeaf.txt";
	fp = fopen(filename1, "w+");
	if (fp == NULL) {
		printf("Cannot open lookupResult file \n");
		exit(0);
	}

	fprintf(fp, "\nSearching in %u leaf:\n",
			gLookupLeaf.size());
	unsigned int indx = 0;
	struct RULE_SET* tmpResultset;

	fprintf(fp, "%-6s%-6s%-6s\n", "Indx", "ReluNum", "ResultSet");
	for (std::vector<struct RULE_SET*>::iterator iter = gLookupLeaf.begin();
			iter != gLookupLeaf.end(); iter++) {
		tmpResultset = *iter;
		fprintf(fp, "%-6u", indx);
		fprintf(fp, "%-6u", tmpResultset->num);
		for (unsigned int i = 0; i < tmpResultset->num; i++) {
			fprintf(fp, "%u ", tmpResultset->ruleList[i]);
		}
		fprintf(fp, "\n");
		indx++;
	}

	fclose(fp);


	/*	writting searched ip index*/
	char filename2[] = "LookupIp.txt";
	fp = fopen(filename2, "w+");
	if (fp == NULL) {
		printf("Cannot open lookupResult file \n");
		exit(0);
	}

	fprintf(fp, "\nSearching %u ips :\n", gLookupIndx.size());
	indx = 0;
	unsigned int tmp_ip;
	for (std::vector<unsigned int>::iterator iter = gLookupIndx.begin();
			iter != gLookupIndx.end(); iter++) {
		tmp_ip = *iter;
		fprintf(fp, "%-6s%-6s\n", "indx", "ip_indx");
		fprintf(fp, "%-6u%-6u\n", indx, tmp_ip);

		indx++;
	}

	fclose(fp);



	return SUCCESS;
}
int WrittenTreeInfo() {
	/*	writting leaf info*/
	FILE *fp;

	char filename1[] = "leaf_info.txt";
	fp = fopen(filename1, "w+");
	if (fp == NULL) {
		printf("Cannot open lookupResult file \n");
		exit(0);
	}

	fprintf(fp, "\nThere are %u leaf nodes in hs-tree:\n", gLeafset.size());
	unsigned int indx = 0;
	struct HS_NODE* tmp_leaf;
	for (std::vector<struct HS_NODE*>::iterator iter = gLeafset.begin();
			iter != gLeafset.end(); iter++) {
		tmp_leaf = *iter;
		fprintf(fp, "%-6s%-6s%-6s\n", "indx", "inc", "rulelist");
		fprintf(fp, "%-6u%-6u", indx, tmp_leaf->ruleset->num);
		for (unsigned int i = 0; i < tmp_leaf->ruleset->num; i++) {
			fprintf(fp, "%u ", tmp_leaf->ruleset->ruleList[i]);
		}
		fprintf(fp, "\n");
		indx++;
	}

	fclose(fp);




	return SUCCESS;
}

int ShowInfo() {
	printf("\n>>input: %s", FILTER_FILE);
	printf("\n>>worst case tree depth:	%d", gWstDepth);
	printf("\n>>average tree depth:		%f", (float) gAvgDepth / gNumLeafNode);
	printf("\n>>number of tree nodes:%d", gNumInterNode);
	printf("\n>>number of leaf nodes:%d", gNumLeafNode);
	printf("\n>>total memory: %d(KB)",
			((gNumInterNode + gNumLeafNode) * 8) >> 10);
	printf("\nMaxMalloc is %u KB", gStatistic.MaxMalloc >> 10);
//	printf("\n%u\n",gRuleset.ruleList[0].range[0][0]);
	return SUCCESS;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  yes, this is where we start.
 * =====================================================================================
 */
int main(int argc, char** argv) {

	int iRet;

	/* load rules from file */
	iRet = ReadFilterFile();
	if (iRet) {
		printf("\n>>Building HyperSplit tree (%u rules, 5-tuple)\n",
				gRuleset.num);
	}

	/* build hyper-split tree */
	iRet = InitRootNode(&gRootnode);
	PROFILE_START
	;
	iRet = BuildHSTree(&gRootnode);
	printf("\n>> Step:BuildHSTree ");
	PROFILE_END
	;

#ifdef	LOOKUP
	iRet = GetIpset();

	PROFILE_START
	;
	iRet = LookUpinHSTree(&gIpset);
	printf("\n>> Step:LookupHSTree ");
	PROFILE_END
	;
#endif

	iRet = WrittenTreeInfo();
	iRet = WrittenLookResults();
	iRet = ShowInfo();

	return SUCCESS;
}

