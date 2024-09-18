#define _CRT_SECURE_NO_WARNINGS
#include "Magma.h"
#include<stdio.h>
#include<time.h>


#define BUFCOUNT 4096 // число блоков длины 8 байт в буфере buf47

uint32 Inverse(uint32 a) {
	return(a >> 24) & 0xff |
		((a >> 16) & 0xff) << 8 |
		((a >> 8) & 0xff) << 16 |
		((a & 0xff) << 24);
}
// Размер файла в байтах
uint64 Size(const char *fname) {
	FILE *f;
	uint64 size;
	if ((f = fopen(fname, "rb")) == NULL)
		return 0;
	fseek(f, 0, SEEK_END); // перемещаем указатель в конец файла
	size = ftell(f); // считываем текущую позицию указателя
	fclose(f);
	return size;
}
// Прибавление 1 по модулю 2^64 к a
void Add_1(Block64 *a) {
	uint64 sum;
	sum = (a->right) + 1;
	(a->right)++;
	(a->left) += (uint32)(sum >> 32);
}
// Шифрование файла fname1 в режиме CTR и получение шифрованного файла fname2 на ключе key

int Encrypt_file_CTR(char *fname1, char *fname2, uint32 *key, uint32 gamma0) {
	FILE *f, *g;
	Block64 buf[BUFCOUNT]; // буфер обмена
	uint64 ullbuf; // 64-битный буфер
	uint64 size, // размер файла в байтах
		q, // число блоков размером 8*BUFCOUNT байт
		m, // число блоков длины 8 байт, которые целиком не покрыли buf
		r; // длина последнего неполного блока, если он имеется
	// счетчики для циклов
	uint64 i;
	int j;
	// (gamma0,gamma1) - блок гаммы
	Block64 gamma;
	// счетчик для получения гаммы
	Block64 ctr;
	// y - вспомогательный блок
	Block64 y;
	if ((f = fopen(fname1, "rb")) == NULL)return -1;
	if ((g = fopen(fname2, "wb")) == NULL) { 
		fclose(f);
		return -2;
	}
	// Вычисляем размер файла, также значения q, m, r
	// size = 8*BUFCOUNT*q + 8*m + r
	size = Size(fname1);
	q = size / (sizeof(Block64) * BUFCOUNT);
	m = (size - sizeof(Block64) * BUFCOUNT * q) / sizeof(Block64);
	r = size - sizeof(Block64) * BUFCOUNT * q - sizeof(Block64) * m;
	ctr.left = gamma0;
	ctr.right = 0;
	for(i = 0; i < q; i++) {
		// считываем кусок файла в буфер
		fread(buf, sizeof(*buf), BUFCOUNT, f);
		// шифруем элементы буфера
		for(j = 0; j < BUFCOUNT; j++) {
			Encrypt(ctr, &gamma, key);
			buf[j].left = Inverse(Inverse(buf[j].left) ^ gamma.left);
			buf[j].right = Inverse(Inverse(buf[j].right) ^ gamma.right);Add_1(&ctr);
		}// записываем зашифрованный буфер в выходной файл
		fwrite(buf, sizeof(*buf), BUFCOUNT, g);
	}
	if (m > 0) // шифруем блок, размер которого меньше размера буфера
	{
		fread(buf, sizeof(*buf), m, f);
		for(j = 0; j < m; j++) {
			Encrypt(ctr, &gamma, key);
			buf[j].left = Inverse(Inverse(buf[j].left) ^ gamma.left);
			buf[j].right = Inverse(Inverse(buf[j].right) ^ gamma.right);
			Add_1(&ctr);
		}
		fwrite(buf, sizeof(*buf), m, g);
	}
	if (r > 0) {
		// считываем последние r байт в переменную ullbuf и шифруем
		fread(&ullbuf, r, 1, f);
		Encrypt(ctr, &gamma, key);
		y.left = Inverse((uint32)(ullbuf >> 32));
		y.right = Inverse((uint32)ullbuf);
		y.left ^= gamma.left;
		y.right ^= gamma.right;
		y.left = Inverse(y.left);
		y.right = Inverse(y.right);
		ullbuf = (uint64)y.left << 32 | y.right;
		fwrite(&ullbuf, r, 1, g);
	}
	fclose(f);
	fclose(g);
	return 0;
}
int main() {
	char fname1[] = "d:\\a.data";
	char fname2[] = "d:\\a.data.magma";
	char fname3[] = "d:\\b.data";
	uint32 key[8]; // ключ размером 256 бит (256 = 8*32)
	// gamma - начальный блок гаммы размером 32 бита
	uint32 gamma;
	int i;
	// !!! Здесь нужна инициализация массива ключей key
	key[0] = 0xffeeddcc; key[1] = 0xbbaa9988;
	key[2] = 0x77665544; key[3] = 0x33221100;
	key[4] = 0xf0f1f2f3; key[5] = 0xf4f5f6f7;
	key[6] = 0xf8f9fafb; key[7] = 0xfcfdfeff;

	gamma = time(NULL); // начальный вектор гаммы
	// Шифруем файл
	printf("Encrypt = %d\n", Encrypt_file_CTR(fname1, fname2, key, gamma));
	// Расшифровываем файл
	printf("Decrypt = %d\n", Encrypt_file_CTR(fname2, fname3, key, gamma));
	return 0;
}
