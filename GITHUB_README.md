# PE文件熵值分析器

## 简介
PE文件熵值分析器是一个用于分析Windows可执行文件(PE文件)熵值的工具。熵值可以用来判断文件是否包含加密或压缩数据，从而帮助识别潜在的恶意软件。

## 功能特点
- 图形用户界面，操作简便
- 显示文件整体熵值和各节的熵值
- 多线程处理，界面不会卡死
- 进度条提示，用户体验更好


## 安装依赖

### 方法1：使用requirements.txt安装
```bash
pip install -r requirements.txt
```

### 方法2：手动安装依赖
```bash
pip install pefile
```

## 使用方法

### Python源码运行
```bash
python EntropyGUICalc.py
```

### 打包后的exe版本
直接运行 `dist\EntropyGUICalc.exe` 文件

## 打包为exe文件

### 安装打包工具
```bash
pip install pyinstaller
```

### 打包命令
```bash
pyinstaller --onefile --windowed EntropyGUICalc.py
```

打包完成后，exe文件将位于 `dist` 目录中。

### 打包参数说明
- `--onefile`: 打包为单个exe文件
- `--windowed`: 隐藏控制台窗口（GUI应用程序）

## 熵值参考范围
- **0.0 - 5.5**: 低随机性，可能为文本或简单数据
- **5.6 - 6.8**: 中等随机性，多数良性文件在此范围
- **6.9 - 7.1**: 较高随机性，需进一步检查
- **7.2 - 8.0**: 高随机性，可能为加密/压缩数据，恶意软件常见范围

## 风险等级评估
- **低风险**: 熵值 < 5.6
- **较低风险**: 熵值 5.6-6.8
- **中等风险**: 熵值 6.9-7.1
- **高风险**: 熵值 ≥ 7.2 (可能为恶意软件)

## 多线程优化
本工具使用多线程技术处理文件分析，即使在分析大型文件时也不会导致界面卡死。分析过程中会显示进度条，让用户了解程序正在运行。

## 项目结构
```
.
├── EntropyGUICalc.py          # 主程序文件
├── requirements.txt           # 依赖列表
├── GITHUB_README.md           # GitHub文档
├── README_EXE.md             # exe版本使用说明
├── USAGE.md                  # 使用说明
├── RunEntropyAnalyzer.bat    # 运行批处理文件
├── dist\                     # 打包输出目录
│   └── EntropyGUICalc.exe    # 打包后的exe文件
├── build\                    # 构建目录
└── sniffnet.exe              # 测试文件
```

## 注意事项
1. 本工具需要Python 3.x环境
2. 如果未安装pefile模块，将无法分析PE节信息
3. 对于非常大的文件，分析可能需要一些时间
4. 熵值分析只是辅助判断手段，不能作为判断恶意软件的唯一依据
5. 打包后的exe文件可能会被某些杀毒软件误报，请将程序添加到白名单