#pragma once
#include <string>
#define MAX_NUM_PER_VARIETY 15
#define VARIETY_NUM 7

// PIR params that have been negotiated
static uint64_t number_of_items = VARIETY_NUM * MAX_NUM_PER_VARIETY;
static uint64_t size_per_item = MAX_NUM_PER_VARIETY * 6; // in bytes 
static uint32_t N = 4096;
static uint32_t logt = 20; // t is coeff modular (plaintext modular) 
static uint32_t d = 2;     // dimension of the database Recommended values: (logt, d) = (20, 2)

// use symmetric encryption instead of public key (recommended for smaller query)
static bool use_symmetric = false;

// pack as many elements as possible into a BFV plaintext (recommended)
static bool use_batching = true;

static bool use_recursive_mod_switching = true;

// database
static std::string Variety[VARIETY_NUM] = {
    "银行", "餐饮", "旅馆", "医疗", "教育", "商场", "其他"
};

static std::string Merchants[VARIETY_NUM][MAX_NUM_PER_VARIETY] = {
    "中国邮政储蓄银行", "中国农业银行", "中国银行", "潍坊银行", "中国人民银行", "交通银行", "中国进出口银行", "中国建设银行", "", "", "", "", "", "", "",
    "万众源排骨米饭", "洪晟泰炉包店", "信隆大包","蓝白小厨","海天混沌","小四季火锅","PLANB咖啡","山海楼","1988 全日餐厅","胡记食之屋","杨铭宇黄焖鸡","晟胜茶社","闲庭咖啡","东北私家菜","景福宫韩国料理",
    "青岛嘉琦旅馆", "青岛盈鑫旅馆", "圆梦圆旅馆", "青岛丽天大酒店", "汉庭酒店", "青岛东海路9号公寓", "桔子水晶酒店", "国利旅馆", "青岛海悦来旅馆", "爱尊客酒店", "景福宫商务宾馆", "", "", "", "",
    "综合门诊", "国风大药店", "湛海医院", "海军971医院", "", "", "", "", "", "", "", "", "", "", "",
    "青岛五十九中学", "海信学校", "市南区实验小学", "老年大学", "", "", "", "", "", "", "", "", "", "", "",
    "湛山市场", "有客便利", "衣品人生", "猫港便利点", "滨海百货", "海鳌海产", "", "", "", "", "", "", "", "", "",
    "中国联通", "中国体育彩票", "电影公社", "景和图文", "中国移动", "通信局", "菜鸟驿站", "", "", "", "", "", "", "", ""
};