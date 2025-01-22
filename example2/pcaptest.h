#ifndef PCAPTEST_H
#define PCAPTEST_H

void TestIpv6(void);

// 测试捕获数据 loop 方式
void testCapLoop(void);

// 测试捕获数据保存为文件
void testCapAndSaveFile(void);

// 测试打开捕获文件并解析
void testOpenCapFile(void);

#endif // PCAPTEST_H