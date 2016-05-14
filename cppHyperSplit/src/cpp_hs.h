/*
 * cpp.hs.h
 *
 *  Created on: 2015Äê10ÔÂ30ÈÕ
 *      Author: 10177270
 */

#ifndef CPP_HS_H_
#define CPP_HS_H_

/*-----------------------------------------------------------------------------
 *  constant
 *-----------------------------------------------------------------------------*/


#define DEBUG_MALLOC
//#define	DEBUG
#define	LOOKUP
//#define	ShowResults
//#define FULLHS
#define HSINC 8

#define FILTER_FILE ".\\filter\\1000"

/* for 5-tuple classification */
#define DIM			5

/* for function return value */
#define SUCCESS		1
#define FAILURE		0
#define TRUE		1
#define FALSE		0

/* for bitmap */
#define MAXFILTERS	65536 /* support 64K rules */
#define WORDLENGTH	32	/* for 32-bit system */
#define BITMAPSIZE	256 /* MAXFILTERS/WORDLENGTH */

/*-----------------------------------------------------------------------------
 *  structure
 *-----------------------------------------------------------------------------*/
struct FILTER {
	unsigned int cost;
	unsigned int dim[DIM][2];
	unsigned char act;
};

struct FILTSET {
	unsigned int numFilters;
	struct FILTER filtArr[MAXFILTERS];
};

struct TPOINT {
	unsigned int value;
	unsigned char flag;
};

struct FRAGNODE {
	unsigned int start;
	unsigned int end;
	struct FRAGNODE *next;
};

struct FRAGLINKLIST {
	unsigned int fragNum;
	struct FRAGNODE *head;
};

struct TFRAG {
	unsigned int value;						// end point value
	unsigned int cbm[BITMAPSIZE];					// LENGTH * SIZE bits, CBM
};

struct TFRAG* ptrTfrag[2];				// released after tMT[2] is generated

struct FRAG {
	unsigned int value;
};

struct FRAG* ptrfrag[2];
unsigned int fragNum[2];

struct CES {
	unsigned short eqID;					// 2 byte, eqID;
	unsigned int cbm[BITMAPSIZE];
	struct CES *next;								// next CES
};

struct LISTEqS {
	unsigned short nCES;					// number of CES
	struct CES *head;								// head pointer of LISTEqS
	struct CES *rear;						// pointer to end node of LISTEqS
};
struct LISTEqS* listEqs[6];

struct PNODE {
	unsigned short cell[65536];			// each cell stores an eqID
	struct LISTEqS listEqs;					// list of Eqs
};
struct PNODE portNodes[2];

/*for hyper-splitting tree*/
struct RULE {
	unsigned int pri;
	unsigned int range[DIM][2];
};

struct RULE_SET {
	unsigned int num; /* number of rules in the rule set */
	struct RULE* ruleList; /* rules in the set */
};

struct seg_point_s {
	unsigned int num; /* number of segment points */
	unsigned int* pointList; /* points stores here */
};

struct segments_s {
	unsigned int num; /* number of segment */
	unsigned int range[2]; /* segment */
};

struct search_space_s {
	unsigned int range[DIM][2];
};

struct HS_NODE {
	unsigned char d2s; /* dimension to split, 2bit is enough */
	unsigned char depth; /* tree depth of the node, x bits supports 2^(2^x) segments */
	unsigned int thresh; /* thresh value to split the current segments */
//	unsigned int		NodeRange[DIM][2];
	struct RULE_SET* ruleset;
	struct HS_NODE* child[2]; /* pointer to child-node, 2 for binary split */

};

struct IP {
//	unsigned int pri;
	unsigned int ip[DIM];
};

struct IPSET {
	unsigned int num; /* number of rules in the rule set */
	struct IP* ipList; /* rules in the set */
};

//struct HS_LEAFSET
//{
//	unsigned int	num;
//	struct HS_NODE*	 head;
//	struct HS_NODE*	 tear;
//} ;


struct STASTIC{
	unsigned int	MaxMalloc;
	unsigned int	currMalloc;

};




/*-----------------------------------------------------------------------------
 *  global
 *-----------------------------------------------------------------------------*/
struct FILTSET filtset; /* filter set for range match */
struct RULE_SET gRuleset;
struct IPSET gIpset;
struct HS_NODE gRootnode;
struct STASTIC gStatistic;

#include <vector>
#include <iterator>
std::vector<struct HS_NODE*> gLeafset;
std::vector<struct HS_NODE*> gNodeStack;
std::vector<struct RULE_SET*> gLookupLeaf;
std::vector<unsigned int> gLookupIndx;

/*-----------------------------------------------------------------------------
 *  function declaration
 *-----------------------------------------------------------------------------*/

/* read rules from file */
int ReadFilterFile();
void LoadFilters(FILE* fp, struct FILTSET* filtset);
int ReadFilter(FILE* fp, struct FILTSET* filtset, unsigned int cost);
void ReadIPRange(FILE* fp, unsigned int* IPrange);
void ReadPort(FILE* fp, unsigned int* from, unsigned int* to);
void ReadProtocol(FILE* fp, unsigned int* from, unsigned int* to);

/* build hyper-split-tree */
int GenSubNode(struct RULE_SET* ruleset, struct HS_NODE* node,
		unsigned int depth); /* main */
int SegPointCompare(const void * a, const void * b);

/* lookup hyper-split-tree */
int LookUpinHSTree(struct IPSET* ptmpIPset);

#endif /* CPP_HS_H_ */
