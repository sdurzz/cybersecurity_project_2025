#姓名:张治瑞

#学号：202200210078


# 密码学算法实现与应用项目集合

本仓库包含6个密码学相关的项目，涵盖了商用密码算法实现、数字水印、零知识证明、以及密码安全检查协议等领域。

## 📋 项目概览

- **Project 1**: SM4加密算法的软件实现和优化
- **Project 2**: 基于数字水印的图片泄露检测
- **Project 3**: Poseidon2哈希算法的Circom电路实现
- **Project 4**: SM3哈希算法的软件实现与优化
- **Project 5**: SM2椭圆曲线数字签名算法的软件实现优化
- **Project 6**: Google Password Checkup协议验证

## 🔐 Project 1: SM4软件实现和优化

### 目标
实现和优化SM4分组密码算法的软件执行效率，并实现SM4-GCM工作模式。

### 技术要点
- **a) SM4算法优化**
  - 基本实现出发
  - T-table查表优化
  - AESNI指令集优化
  - 最新指令集优化（GFNI、VPROLD等）
- **b) SM4-GCM模式**
  - 基于优化的SM4实现
  - GCM工作模式的软件优化



## 🖼️ Project 2: 基于数字水印的图片泄露检测

### 目标
实现图片数字水印的嵌入和提取功能，并进行鲁棒性测试。

### 功能特性
- 数字水印嵌入算法
- 数字水印提取算法
- 鲁棒性测试（翻转、平移、截取、对比度调整等）
- 可基于开源项目二次开发



## ⚡ Project 3: Poseidon2哈希算法Circom电路实现

### 目标
使用Circom实现Poseidon2哈希算法的零知识证明电路。

### 技术规格
- **哈希参数**: (n,t,d) = (256,3,5) 或 (256,2,5)
- **电路设计**: 
  - 公开输入：poseidon2哈希值
  - 隐私输入：哈希原象
  - 输入限制：一个block
- **证明系统**: Groth16算法

### 参考资料
- [Poseidon2论文](https://eprint.iacr.org/2023/323.pdf)
- [Circom文档](https://docs.circom.io/)
- [Circom电路样例](https://github.com/iden3/circomlib)



## 🔍 Project 4: SM3软件实现与优化

### 目标
实现和优化SM3哈希算法，并进行安全性分析和应用验证。

### 功能模块
- **a) SM3算法优化**
  - 基本软件实现
  - 执行效率优化（参考付勇老师PPT）
- **b) Length-extension攻击验证**
  - 实现length-extension attack
  - 安全性分析
- **c) Merkle树构建**
  - 基于RFC6962构建Merkle树
  - 支持10万叶子节点
  - 存在性证明和不存在性证明




## 📝 Project 5: SM2软件实现优化

### 目标
实现SM2椭圆曲线数字签名算法，并验证签名算法的安全问题。

### 实现要点
- **a) 基础实现**
  - 推荐使用Python实现
  - SM2算法基础功能
  - 各种算法改进尝试
- **b) 签名误用验证**
  - 基于20250713-wen-sm2-public.pdf
  - POC验证实现
  - 推导文档和验证代码
- **c) 数字签名伪造**
  - 伪造中本聪的数字签名
  - 安全性分析



## 🔐 Project 6: Google Password Checkup验证

### 目标
实现Google Password Checkup协议，验证密码安全检查机制。

### 技术规格
- 基于[论文](https://eprint.iacr.org/2019/723.pdf) Section 3.1
- 实现Figure 2展示的协议
- 编程语言不限




## 🛠️ 技术栈

- **编程语言**: C/C++, Python, JavaScript
- **密码学库**: OpenSSL, Crypto++
- **零知识证明**: Circom, snarkjs
- **构建工具**: CMake, Make
- **测试框架**: Google Test, pytest

## 🚀 快速开始

### 环境要求
```bash
# 基础环境
gcc/clang
python3
node.js
cmake

# 密码学库
sudo apt-get install libssl-dev

# Circom环境
npm install -g circom
npm install -g snarkjs
```

### 编译和运行
```bash
# 克隆仓库
git clone <repository-url>
cd cryptography-projects

# 进入具体项目目录
cd project1

# 编译
make all

# 运行测试
make test
```

## 📊 性能基准

各项目都包含详细的性能测试，可以通过以下命令运行：

```bash
# SM4性能测试
cd project1-sm4 && make benchmark

# SM3性能测试  
cd project4-sm3 && make benchmark

# SM2性能测试
cd project5-sm2 && python benchmark.py
```

## 📖 文档

每个项目目录下都包含详细的README和技术文档：
- 算法原理说明
- 实现细节
- 优化策略
- 安全性分析
- 性能测试结果

## 🤝 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🔗 参考资料

- [GM/T 0002-2012 SM4分组密码算法](http://www.gmbz.org.cn/)
- [GM/T 0004-2012 SM3密码杂凑算法](http://www.gmbz.org.cn/)
- [GM/T 0003-2012 SM2椭圆曲线公钥密码算法](http://www.gmbz.org.cn/)
- [RFC6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [Poseidon2 Hash Function](https://eprint.iacr.org/2023/323.pdf)
- [Google Password Checkup](https://eprint.iacr.org/2019/723.pdf)


---

*本项目仅用于学术研究和教学目的，请遵守相关法律法规。*
