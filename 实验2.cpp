#include <iostream>
#include <openssl/x509.h>
#include<algorithm>
using namespace std;

/*获取并显示证书版本号函数，成功执行返回0，否则返回-1*/
int getVersion(X509* cert) {
    int version = X509_get_version(cert);
    if (!version) {
        cout << "获取证书版本号失败" << endl;
        return -1;
    }
    switch (version)
    {
    case 0:		
        cout << "版本：V" << version + 1 << endl;
        break;
    case 1:		
        cout << "版本：V"<<version + 1<< endl;
        break;
    case 2:		
        cout << "版本：V" << version + 1 << endl;
        break;
    default:    
        cout << "版本号错误" << endl;
        return -1;
    }
    return 0;
}

/*读取并显示证书序列号函数，成功执行返回0，否则返回-1*/
int  getSerialNumber(X509* cert){
    char* res = NULL;
    ASN1_INTEGER* serialASN1 = NULL;
    BIGNUM* serisalNumber = NULL;
    /*获取证书序列号*/
    serialASN1 = X509_get_serialNumber(cert);
    if (serialASN1->length == 0) {
        cout << "获取序列号失败" << endl;
        return -1;
    }
    /*将序列号从ASN1 Integer类型转换为BigNum结构*/
    serisalNumber = ASN1_INTEGER_to_BN(serialASN1, NULL);
    /*转换为16进制存储在字符串中*/
    res = BN_bn2hex(serisalNumber);
    cout << "序列号: " << res << endl;
    /*释放指针*/
    OPENSSL_free(res);
    BN_free(serisalNumber);
    return 0;
}

/*获取签名算法函数，成功执行返回0，否则返回-1*/
int getSignatureAlgorithm(X509* cert) {
    char oid[128] = { 0 };
    const X509_ALGOR* salg = NULL;
    /*获取签名算法oid*/
    salg = X509_get0_tbs_sigalg(cert);
    if (!salg) {
        cout << "获取签名算法OID失败" << endl;
        return -1;
    }
    /*转码*/
    OBJ_obj2txt(oid, 128, salg->algorithm, 1);
    string signNumOid = string(oid);
    /*判断oid对应的算法，如果是SHA256RSA输出算法名称，否则输出其oid*/
    if (signNumOid == "1.2.840.113549.1.1.11") {
        cout << "签名算法名称: sha256RSA" << endl;
    }
    else {
        cout << "签名算法OID: " << signNumOid << endl;
    }
    return 0;
}

/*获取证书签发者函数，成功执行返回0，否则返回-1*/
int getIssuerName(X509* cert) {
    /*获取签发者信息*/
    X509_NAME* X509IssuerName = X509_get_issuer_name(cert);
    if (!X509IssuerName) {
        cout << "获取证书签发者失败" << endl;
        return -1;
    }
    /*进行格式转换*/
    char* issuerName = X509_NAME_oneline(X509IssuerName, NULL, 0);
    string issuerNameStr = string(issuerName);
    /*将转换后的内容中的无关符号替换并输出签发者信息*/
    replace(issuerNameStr.begin(), issuerNameStr.end(), '/', ' ');
    cout << "证书签发者: " << issuerNameStr << endl;
    return 0;
}

/*UTC时间转换为北京时间函数*/
void getBeiJingTime(tm* time) {
    int year, month, day, hour, min, sec, monthTotalDay = 0;
    year = time->tm_year + 1900;
    month = time->tm_mon + 1;
    day = time->tm_mday;
    hour = time->tm_hour + 8;
    min = time->tm_min;
    sec = time->tm_sec;
    /*判断月份以确定天数*/
    if (month == 4 || month == 6 || month == 9 || month == 11)
    {
        monthTotalDay = 31;
    }
    else if (month == 2)
    {
        if ((year % 400 == 0) || (year % 4 == 0 && year % 100 != 0))
            monthTotalDay = 29;
        else
            monthTotalDay = 28;
    }
    else
    {
        monthTotalDay = 30;
    }
    /*小时部分转换成北京时间后如果大于23点则需要更改天数*/
    if (hour > 23) {
        hour = hour % 23;
        day = day + 1;
        /*判断更改后的天数是否超过对应月份总天数，若超过则需要更改月份信息*/
        if (day > monthTotalDay) {
            day = day % monthTotalDay;
            month = month + 1;
            /*如果更改后月份大于12月，则需要更改年份信息*/
            if (month > 12)
            {
                month = month % 12;
                year = year + 1;
            }
        }
    }
    printf("%d年%02d月%02d日 %02d:%02d:%02d", year, month, day, hour, min, sec);
}

/*获取证书有效期函数*/
void getValidTerm(X509* cert) {
    /*获取开始时间*/
    ASN1_TIME* startTime = X509_getm_notBefore(cert);
    /*获取结束时间*/
    ASN1_TIME* endTime = X509_getm_notAfter(cert);
    /*ASN1_TIME类型转为tm结构*/
    tm* tm_startTime = (tm*)malloc(128);
    tm* tm_endTime = (tm*)malloc(128);
    ASN1_TIME_to_tm(startTime, tm_startTime);
    ASN1_TIME_to_tm(endTime, tm_endTime);
    cout << "有效期从: ";
    getBeiJingTime(tm_startTime);
    cout << " 到 ";
    getBeiJingTime(tm_endTime);
    cout << endl;
}

/*获取证书持有者函数，成功执行返回0，否则返回-1*/
int getSubjectName(X509 * cert) {
    /*获取持有者信息*/
    X509_NAME* X509SubjectName = X509_get_subject_name(cert);
    if (!X509SubjectName){
        cout << "获取证书持有者失败" << endl;
        return -1;
    }
    /*进行格式转换*/
    char* subjectName = X509_NAME_oneline(X509SubjectName, NULL, 0);
    string subjectNameStr = string(subjectName);
    /*将转换后的内容中的无关符号替换并输出持有者信息*/
    replace(subjectNameStr.begin(), subjectNameStr.end(), '/', ' ');
    cout << "证书持有者: " << subjectNameStr << endl;
    return 0;
}

/*获取证书公钥信息函数，，成功执行返回0，否则返回-1*/
int getPublicKey(X509* cert) {
    ASN1_BIT_STRING* X509PKEY;
    X509PKEY = X509_get0_pubkey_bitstr(cert);
    if (!X509PKEY) {
        return -1;
    }
    unsigned char* temp_buf = NULL;
    temp_buf = (unsigned char*)malloc(X509PKEY->length);
    temp_buf = X509PKEY->data;
    int i;
    /*按指定格式输出公钥*/
    cout<<"证书持有者公钥："<<endl;
    for (i = 0; i < X509PKEY->length; i++)
    {
        printf("%02X%c", temp_buf[i], (i + 1) % 20 == 0 ? '\n' : ' ');
    }
    cout << endl;
    return 0;
}

int main()
{
    BIO* cert1In = NULL;
    BIO* cert2In = NULL;
    /*生成IO对象*/
    cert1In = BIO_new(BIO_s_file());
    cert2In = BIO_new(BIO_s_file());
    /*将证书文件读入IO*/
    BIO_read_filename(cert1In, "der_certificate01.cer");//u1.cer
    BIO_read_filename(cert2In, "der_certificate02.cer");//cacert.cer
    if (cert1In == NULL||cert2In==NULL){
        perror("证书读入IO失败");
        return -1;
    }
    /*解码证书文件转换为内部结构*/
    X509* cert1,*cert2;
    cert1 = d2i_X509_bio(cert1In, NULL);
    cert2 = d2i_X509_bio(cert2In, NULL);
    if (cert1 == NULL || cert2 == NULL) {
        printf("转换证书结构失败\n");
        return -1;
    }
    cout << "证书certificate01信息" << endl;
    /*获取证书版本号*/
    getVersion(cert1);
    /*获取序列号*/
    getSerialNumber(cert1);
    /*获取签名算法*/
    getSignatureAlgorithm(cert1);
    /*获取证书颁发者*/
    getIssuerName(cert1);
    /*获取证书有效期*/
    getValidTerm(cert1);
    /*获取证书使用者*/
    getSubjectName(cert1);
    /*获取证书公钥*/
    getPublicKey(cert1);
    cout << endl;
    cout << "证书certificate02信息" << endl;
    getVersion(cert2);
    getSerialNumber(cert2);
    getSignatureAlgorithm(cert2);
    getIssuerName(cert2);
    getValidTerm(cert2);
    getSubjectName(cert2);
    getPublicKey(cert2);

    /*证书2验证证书1*/
    EVP_PKEY* k1, * k2;
    k1= X509_get_pubkey(cert1);
    k2 = X509_get_pubkey(cert2);
    int ret = X509_verify(cert1, k2);
    if(ret)
        cout << endl << "certificate02验证certificate01结果：验证成功" << endl;
    else
        cout << endl << "certificate02验证certificate01结果：验证失败" << endl;
    X509_free(cert1);
    X509_free(cert2);
    BIO_free(cert1In);
    BIO_free(cert2In);
    return 0;
}
