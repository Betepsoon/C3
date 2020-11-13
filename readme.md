C3破解
____
```py
from Crypto.Cipher import AES
from hashlib import sha1
import base64
import re
import binascii


def sha_calculate(input_str: str):
	sha_tool = sha1.new()
	sha_tool.update(input_str.encode())
	return sha_tool.hexdigest()[:32]


def adjustment_odd_even(key):
	'''
	如果1的个数为偶数，最后添1
	如果1的个数为奇数，最后添0
	'''
	final_k = []
	for i in key:
		if bin(int(i, 16) >> 1).count('1') % 2 == 0:  # 奇偶校验
			temp_k = hex(1 + (int(i, 16) >> 1 << 1))
			final_k += [temp_k[2:].zfill(2)]
		else:
			temp_k = hex(int(i, 16) >> 1 << 1)
			final_k += [temp_k[2:].zfill(2)]
	return ''.join(final_k)


def aes_decryption(ciphertext: bytes, key: bytes):
	cipher = AES.new(key, AES.MODE_CBC, binascii.a2b_hex('0' * 32))
	return cipher.decrypt(ciphertext)


if __name__ == '__main__':
	weighting = [7, 3, 1] * 2
	date = [1, 1, 1, 1, 1, 6]
	check_digit = sum([weighting[i] * date[i] for i in range(6)]) % 10  # 7
	ciphertext = base64.b64decode(
		'9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI')
	visa_code = '12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4'
	visa_number = visa_code[0: 9]  # 签证号
	visa_number_digit = visa_code[9]  # 证件号码的校验位数
	nation = visa_code[10:13]  # 国籍
	birth_day = visa_code[13:19]  # 持有人出生日期
	birth_digit = visa_code[19]  # 出生日期校验位数
	sex = visa_code[20]  # 出生日期校验位数
	visa_date = visa_code[21:27]  # 签证到期日期
	date_digit = visa_code[27]  # 到期日校验位数
	mrz_info = visa_number + visa_number_digit + birth_day + birth_digit + visa_date + date_digit
	k_seed = sha1(mrz_info.encode('utf8')).hexdigest()[:32]  # 16字节生成密钥种子
	c = '00000001'
	# 连接K_seed和c：
	D = binascii.a2b_hex(k_seed + c)
	# 计算D的SHA-1散列
	d_sha = sha1(D).hexdigest()[:32]
	# 得到Ka与Kb
	ka = d_sha[:16]
	kb = d_sha[16:]
	# 调整奇偶校验位
	ka = adjustment_odd_even(re.findall('.{2}', ka))
	kb = adjustment_odd_even(re.findall('.{2}', kb))
	key = ka + kb
	print(aes_decryption(ciphertext, binascii.a2b_hex(key)))
```
