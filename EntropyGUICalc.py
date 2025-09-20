import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import math
import os
from typing import Union
import threading
import time

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

class EntropyAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PE文件熵值分析器")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 创建界面元素
        self.create_widgets()
        
        # 存储分析结果
        self.results = []
        
        # 进度条
        self.progress = None
        self.progress_window = None
        
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # 标题
        title_label = ttk.Label(main_frame, text="PE文件熵值分析器", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(main_frame, text="文件选择", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="选择PE文件:").grid(row=0, column=0, sticky=tk.W)
        
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=50)
        self.file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 10))
        
        browse_button = ttk.Button(file_frame, text="浏览...", command=self.browse_file)
        browse_button.grid(row=0, column=2, sticky=tk.E)
        
        # 拖拽区域（简化实现）
        drag_frame = ttk.LabelFrame(main_frame, text="拖拽区域", padding="20")
        drag_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        drag_frame.columnconfigure(0, weight=1)
        drag_frame.rowconfigure(0, weight=1)
        
        self.drop_area = tk.Label(drag_frame, text="将PE文件拖拽到这里\n或点击浏览按钮选择文件", 
                                 relief="groove", anchor="center", justify="center",
                                 bg="#f0f0f0", fg="#666666", font=("Arial", 12))
        self.drop_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 绑定点击事件到拖拽区域
        self.drop_area.bind("<Button-1>", self.browse_file)
        
        # 分析按钮
        analyze_button = ttk.Button(main_frame, text="分析熵值", command=self.start_analysis_thread)
        analyze_button.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        # 结果显示区域
        result_frame = ttk.LabelFrame(main_frame, text="分析结果", padding="10")
        result_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        # 创建Treeview来显示结果
        columns = ("section", "entropy", "description")
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=10)
        
        # 定义列标题
        self.result_tree.heading("section", text="节名称")
        self.result_tree.heading("entropy", text="熵值")
        self.result_tree.heading("description", text="描述")
        
        # 设置列宽
        self.result_tree.column("section", width=150)
        self.result_tree.column("entropy", width=100)
        self.result_tree.column("description", width=400)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        
        self.result_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # 统计信息区域
        stats_frame = ttk.Frame(main_frame)
        stats_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(3, weight=1)
        
        ttk.Label(stats_frame, text="文件整体熵值:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W)
        self.total_entropy_var = tk.StringVar(value="N/A")
        ttk.Label(stats_frame, textvariable=self.total_entropy_var, font=("Arial", 10)).grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(stats_frame, text="恶意软件风险:", font=("Arial", 10, "bold")).grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        self.risk_var = tk.StringVar(value="N/A")
        ttk.Label(stats_frame, textvariable=self.risk_var, font=("Arial", 10)).grid(row=0, column=3, sticky=tk.W, padx=(10, 0))
        
        # 熵值参考信息
        info_frame = ttk.LabelFrame(main_frame, text="熵值参考", padding="10")
        info_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        info_text = "熵值参考:\n" \
                   "• 0.0 - 5.5: 低随机性，可能为文本或简单数据\n" \
                   "• 5.6 - 6.8: 中等随机性，多数良性文件在此范围\n" \
                   "• 6.9 - 7.1: 较高随机性，需进一步检查\n" \
                   "• 7.2 - 8.0: 高随机性，可能为加密/压缩数据，恶意软件常见范围"
        
        info_label = ttk.Label(info_frame, text=info_text, justify=tk.LEFT)
        info_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
    def browse_file(self, event=None):
        """浏览文件"""
        file_path = filedialog.askopenfilename(
            title="选择PE文件",
            filetypes=[("PE文件", "*.exe *.dll"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            
    def calc_entropy(self, buffer: Union[bytes, str]) -> float:
        """计算给定缓冲区的熵值"""
        if isinstance(buffer, str):
            buffer = buffer.encode()
        
        if len(buffer) == 0:
            return 0.0
            
        entropy = 0.0
        for x in range(256):
            p = float(buffer.count(bytes([x]))) / len(buffer)
            if p > 0:
                entropy += -p * math.log(p, 2)
        return entropy
        
    def get_entropy_description(self, entropy: float) -> str:
        """根据熵值返回描述"""
        if entropy < 5.6:
            return "低随机性，可能为文本或简单数据"
        elif entropy < 6.9:
            return "中等随机性，多数良性文件在此范围"
        elif entropy < 7.2:
            return "较高随机性，需进一步检查"
        else:
            return "高随机性，可能为加密/压缩数据，恶意软件常见范围"
            
    def get_risk_level(self, entropy: float) -> str:
        """根据熵值返回风险等级"""
        if entropy < 5.6:
            return "低风险"
        elif entropy < 6.9:
            return "较低风险"
        elif entropy < 7.2:
            return "中等风险"
        else:
            return "高风险 - 可能为恶意软件"
            
    def start_analysis_thread(self):
        """启动分析线程"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("警告", "请选择一个文件")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("错误", "文件不存在")
            return
            
        # 创建并启动分析线程
        analysis_thread = threading.Thread(target=self.analyze_file_thread, args=(file_path,))
        analysis_thread.daemon = True
        analysis_thread.start()
        
        # 显示进度条
        self.show_progress()
        
    def show_progress(self):
        """显示进度条"""
        if self.progress_window is None or not self.progress_window.winfo_exists():
            self.progress_window = tk.Toplevel(self.root)
            self.progress_window.title("分析中...")
            self.progress_window.geometry("300x100")
            self.progress_window.resizable(False, False)
            
            # 居中显示
            self.progress_window.transient(self.root)
            self.progress_window.grab_set()
            
            progress_frame = ttk.Frame(self.progress_window, padding="20")
            progress_frame.pack(expand=True, fill=tk.BOTH)
            
            ttk.Label(progress_frame, text="正在分析文件，请稍候...").pack(pady=(0, 10))
            
            self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
            self.progress.pack(expand=True, fill=tk.X)
            self.progress.start(10)
            
    def hide_progress(self):
        """隐藏进度条"""
        if self.progress_window is not None and self.progress_window.winfo_exists():
            self.progress.stop()
            self.progress_window.destroy()
            self.progress_window = None
            self.progress = None
            
    def analyze_file_thread(self, file_path):
        """在后台线程中分析文件熵值"""
        try:
            # 清空之前的结果
            self.root.after(0, self.clear_results)
            
            # 计算整个文件的熵值
            with open(file_path, 'rb') as f:
                file_data = f.read()
                total_entropy = self.calc_entropy(file_data)
                
            # 更新UI
            self.root.after(0, self.update_file_entropy, total_entropy)
                
            # 分析PE节
            if HAS_PEFILE:
                pe = pefile.PE(file_path)
                results = []
                
                for section in pe.sections:
                    section_name = section.Name.decode().rstrip('\x00')
                    section_data = section.get_data()
                    entropy = self.calc_entropy(section_data)
                    description = self.get_entropy_description(entropy)
                    
                    # 保存结果
                    results.append({
                        "section": section_name,
                        "entropy": entropy,
                        "description": description
                    })
                    
                    # 更新UI
                    self.root.after(0, self.update_section_result, section_name, entropy, description)
                    
                pe.close()
                
                # 更新结果列表
                self.root.after(0, self.update_results, results)
            else:
                self.root.after(0, self.show_pefile_warning)
                
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
        finally:
            # 隐藏进度条
            self.root.after(0, self.hide_progress)
            
    def clear_results(self):
        """清空之前的结果"""
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
            
    def update_file_entropy(self, total_entropy):
        """更新文件熵值显示"""
        self.total_entropy_var.set(f"{total_entropy:.5f}")
        self.risk_var.set(self.get_risk_level(total_entropy))
        
    def update_section_result(self, section_name, entropy, description):
        """更新节结果显示"""
        self.result_tree.insert("", "end", values=(section_name, f"{entropy:.5f}", description))
        
    def update_results(self, results):
        """更新结果列表"""
        self.results = results
        
    def show_pefile_warning(self):
        """显示pefile警告"""
        messagebox.showwarning("警告", "pefile模块未安装，无法分析PE节信息\n请运行: pip install pefile")
        
    def show_error(self, error_message):
        """显示错误信息"""
        messagebox.showerror("错误", f"分析文件时出错:\n{error_message}")

def main():
    root = tk.Tk()
    app = EntropyAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()