from __future__ import annotations

import json
import os
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .ai_client import ask_openai
from .default_prompt import DEFAULT_ANALYSIS_PROMPT
from .engine import SolverEngine
from .models import Target
from .utils import DEFAULT_FLAG_PATTERNS, read_targets


class CtfBotGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Rad Solver v{__version__}")
        self.geometry("1120x760")
        self.minsize(900, 620)
        self.report: dict[str, object] | None = None

        self.input_var = tk.StringVar()
        self.flag_var = tk.StringVar()
        self.challenge_name_var = tk.StringVar()
        self.flag_format_var = tk.StringVar(value="FLAG{}")
        self.model_var = tk.StringVar(value=os.environ.get("OPENAI_MODEL", "gpt-5.2"))
        self.api_key_var = tk.StringVar(value=os.environ.get("OPENAI_API_KEY", ""))
        self.provider_var = tk.StringVar(value=os.environ.get("AI_PROVIDER", "openai"))
        self.api_mode_var = tk.StringVar(value=os.environ.get("AI_API_MODE", "responses"))
        self.base_url_var = tk.StringVar(value=os.environ.get("AI_BASE_URL", ""))
        self.template_var = tk.StringVar(value="All Fields")
        self.status_var = tk.StringVar(value="Ready")

        self._build()

    def _build(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        analysis_tab = ttk.Frame(self.notebook, padding=8)
        prompt_tab = ttk.Frame(self.notebook, padding=8)
        ai_tab = ttk.Frame(self.notebook, padding=8)
        ai_result_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(analysis_tab, text="Analysis")
        self.notebook.add(prompt_tab, text="Prompt")
        self.notebook.add(ai_tab, text="AI Settings")
        self.notebook.add(ai_result_tab, text="AI Result")

        analysis_tab.columnconfigure(0, weight=1)
        analysis_tab.rowconfigure(1, weight=1)
        prompt_tab.columnconfigure(0, weight=1)
        prompt_tab.rowconfigure(1, weight=1)
        ai_tab.columnconfigure(0, weight=1)
        ai_result_tab.columnconfigure(0, weight=1)
        ai_result_tab.rowconfigure(0, weight=1)

        target = ttk.LabelFrame(analysis_tab, text="Target")
        target.grid(row=0, column=0, sticky="ew")
        target.columnconfigure(1, weight=1)

        ttk.Button(target, text="File", command=self.pick_file).grid(row=0, column=0, padx=6, pady=8)
        ttk.Entry(target, textvariable=self.input_var).grid(row=0, column=1, sticky="ew", padx=6, pady=8)
        ttk.Button(target, text="Folder", command=self.pick_folder).grid(row=0, column=2, padx=6, pady=8)
        ttk.Button(target, text="Scan", command=self.start_scan).grid(row=0, column=3, padx=6, pady=8)
        ttk.Button(target, text="Solve with AI", command=self.start_solve_with_ai).grid(row=0, column=4, padx=6, pady=8)

        result_box = ttk.Frame(analysis_tab)
        result_box.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        result_box.columnconfigure(0, weight=1)
        result_box.rowconfigure(0, weight=3)
        result_box.rowconfigure(1, weight=2)

        columns = ("score", "category", "title", "value", "source")
        self.tree = ttk.Treeview(result_box, columns=columns, show="headings")
        for column, width in {
            "score": 80,
            "category": 110,
            "title": 220,
            "value": 260,
            "source": 360,
        }.items():
            self.tree.heading(column, text=column.title())
            self.tree.column(column, width=width, anchor=tk.W)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected)
        tree_scroll = ttk.Scrollbar(result_box, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.detail_text = tk.Text(result_box, height=10, wrap="word", state=tk.DISABLED)
        self.detail_text.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        detail_scroll = ttk.Scrollbar(result_box, orient=tk.VERTICAL, command=self.detail_text.yview)
        detail_scroll.grid(row=1, column=1, sticky="ns", pady=(10, 0))
        self.detail_text.configure(yscrollcommand=detail_scroll.set)

        prompt_box = ttk.LabelFrame(prompt_tab, text="Prompt Editor")
        prompt_box.grid(row=0, column=0, sticky="nsew")
        prompt_box.columnconfigure(0, weight=1)
        prompt_box.rowconfigure(1, weight=1)
        prompt_box.rowconfigure(3, weight=2)

        challenge_info = ttk.Frame(prompt_box)
        challenge_info.grid(row=0, column=0, columnspan=2, sticky="ew", padx=6, pady=(6, 0))
        challenge_info.columnconfigure(1, weight=1)
        challenge_info.columnconfigure(3, weight=1)
        ttk.Label(challenge_info, text="Problem name").grid(row=0, column=0, sticky="w")
        ttk.Entry(challenge_info, textvariable=self.challenge_name_var).grid(row=0, column=1, sticky="ew", padx=(8, 12))
        ttk.Label(challenge_info, text="Flag format").grid(row=0, column=2, sticky="w")
        ttk.Entry(challenge_info, textvariable=self.flag_format_var).grid(row=0, column=3, sticky="ew", padx=(8, 0))

        description_frame = ttk.LabelFrame(prompt_box, text="Problem description")
        description_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)
        description_frame.columnconfigure(0, weight=1)
        description_frame.rowconfigure(0, weight=1)
        self.description_text = tk.Text(description_frame, height=5, wrap="word", undo=True)
        self.description_text.grid(row=0, column=0, sticky="nsew")
        description_scroll = ttk.Scrollbar(description_frame, orient=tk.VERTICAL, command=self.description_text.yview)
        description_scroll.grid(row=0, column=1, sticky="ns")
        self.description_text.configure(yscrollcommand=description_scroll.set)

        instruction_frame = ttk.LabelFrame(prompt_box, text="Analysis prompt / instructions")
        instruction_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)
        instruction_frame.columnconfigure(0, weight=1)
        instruction_frame.rowconfigure(0, weight=1)
        self.prompt_text = tk.Text(prompt_box, height=7, wrap="word", undo=True)
        self.prompt_text = tk.Text(instruction_frame, height=9, wrap="word", undo=True)
        self.prompt_text.grid(row=0, column=0, sticky="nsew")
        self.prompt_text.insert("1.0", DEFAULT_ANALYSIS_PROMPT)
        prompt_scroll = ttk.Scrollbar(instruction_frame, orient=tk.VERTICAL, command=self.prompt_text.yview)
        prompt_scroll.grid(row=0, column=1, sticky="ns")
        self.prompt_text.configure(yscrollcommand=prompt_scroll.set)

        options = ttk.Frame(prompt_box)
        options.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=(0, 6))
        options.columnconfigure(1, weight=1)
        ttk.Label(options, text="Extra flag regex").grid(row=0, column=0, sticky="w")
        ttk.Entry(options, textvariable=self.flag_var).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(options, text="Load Prompt", command=self.load_prompt).grid(row=0, column=2)
        ttk.Combobox(
            options,
            textvariable=self.template_var,
            values=("All Fields", "Reversing", "Crypto", "Forensics", "Pwn", "Web", "Custom Flag"),
            state="readonly",
            width=14,
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Button(options, text="Add Prompt", command=self.add_prompt_template).grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Button(options, text="Clear Prompt", command=self.clear_prompt).grid(row=1, column=2, pady=(6, 0))

        ai_box = ttk.LabelFrame(ai_tab, text="AI Provider Settings")
        ai_box.grid(row=0, column=0, sticky="ew")
        ai_box.columnconfigure(1, weight=1)
        ai_box.columnconfigure(3, weight=1)
        ai_box.columnconfigure(5, weight=1)
        ttk.Label(ai_box, text="Provider").grid(row=0, column=0, padx=6, pady=8, sticky="w")
        ttk.Combobox(
            ai_box,
            textvariable=self.provider_var,
            values=("openai", "openai_compatible", "anthropic", "gemini", "ollama"),
            state="readonly",
            width=18,
        ).grid(row=0, column=1, padx=6, pady=8, sticky="ew")
        ttk.Label(ai_box, text="Model").grid(row=0, column=2, padx=6, pady=8, sticky="w")
        ttk.Entry(ai_box, textvariable=self.model_var, width=22).grid(row=0, column=3, padx=6, pady=8, sticky="ew")
        ttk.Button(ai_box, text="AI Analyze", command=self.start_ai_analysis).grid(row=0, column=4, padx=6, pady=8)
        ttk.Label(ai_box, text="API Key").grid(row=1, column=0, padx=6, pady=(0, 8), sticky="w")
        ttk.Entry(ai_box, textvariable=self.api_key_var, show="*", width=28).grid(row=1, column=1, padx=6, pady=(0, 8), sticky="ew")
        ttk.Label(ai_box, text="Mode").grid(row=1, column=2, padx=6, pady=(0, 8), sticky="w")
        ttk.Combobox(
            ai_box,
            textvariable=self.api_mode_var,
            values=("responses", "chat_completions"),
            state="readonly",
            width=18,
        ).grid(row=1, column=3, padx=6, pady=(0, 8), sticky="ew")
        ttk.Label(ai_box, text="Base URL").grid(row=2, column=0, padx=6, pady=(0, 8), sticky="w")
        ttk.Entry(ai_box, textvariable=self.base_url_var).grid(row=2, column=1, columnspan=4, padx=6, pady=(0, 8), sticky="ew")

        ai_result_box = ttk.LabelFrame(ai_result_tab, text="AI Answer")
        ai_result_box.grid(row=0, column=0, sticky="nsew")
        ai_result_box.columnconfigure(0, weight=1)
        ai_result_box.rowconfigure(0, weight=1)
        self.ai_result_text = tk.Text(ai_result_box, wrap="word", state=tk.DISABLED)
        self.ai_result_text.grid(row=0, column=0, sticky="nsew")
        ai_result_scroll = ttk.Scrollbar(ai_result_box, orient=tk.VERTICAL, command=self.ai_result_text.yview)
        ai_result_scroll.grid(row=0, column=1, sticky="ns")
        self.ai_result_text.configure(yscrollcommand=ai_result_scroll.set)

        footer = ttk.Frame(root)
        footer.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        ttk.Button(footer, text="Save JSON", command=self.save_json).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(footer, text="Clear", command=self.clear).grid(row=0, column=2, padx=(8, 0))

    def pick_file(self) -> None:
        path = filedialog.askopenfilename(title="Select CTF challenge file")
        if path:
            self.input_var.set(path)

    def pick_folder(self) -> None:
        path = filedialog.askdirectory(title="Select CTF challenge folder")
        if path:
            self.input_var.set(path)

    def load_prompt(self) -> None:
        path = filedialog.askopenfilename(title="Load prompt text", filetypes=[("Text", "*.txt *.md"), ("All", "*.*")])
        if not path:
            return
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        self.prompt_text.delete("1.0", tk.END)
        self.prompt_text.insert("1.0", content)

    def add_prompt_template(self) -> None:
        templates = {
            "All Fields": DEFAULT_ANALYSIS_PROMPT,
            "Reversing": "reversing challenge. Extract flag, password/serial/magic number, XOR/stack strings, and suspicious comparison constants.",
            "Crypto": "crypto challenge. Try recursive decoding, base encodings, ROT/Caesar, XOR, hash identification, and small RSA if n/e/c are present.",
            "Forensics": "forensics challenge. Check file signatures, strings, UTF-16, embedded archives, PNG text chunks, PDF secrets, and trailing data.",
            "Pwn": "pwn challenge. Identify ELF hints, dangerous functions, ret2win, /bin/sh, ROP markers, and format string payload candidates.",
            "Web": "web challenge. Check comments, hidden paths, JWT, robots.txt, source maps, backup files, SQLi/XSS/SSTI hints, and decoded JS strings.",
            "Custom Flag": "flag format: FLAG{}",
        }
        text = templates.get(self.template_var.get(), "")
        if not text:
            return
        current = self.prompt_text.get("1.0", tk.END).strip()
        prefix = "\n" if current else ""
        self.prompt_text.insert(tk.END, prefix + text + "\n")

    def clear_prompt(self) -> None:
        self.prompt_text.delete("1.0", tk.END)

    def _structured_prompt(self) -> str:
        parts = []
        if self.challenge_name_var.get().strip():
            parts.append(f"Problem name: {self.challenge_name_var.get().strip()}")
        if self.flag_format_var.get().strip():
            parts.append(f"Flag format: {self.flag_format_var.get().strip()}")
        description = self.description_text.get("1.0", tk.END).strip()
        if description:
            parts.append("Problem description:\n" + description)
        body = self.prompt_text.get("1.0", tk.END).strip()
        if body:
            parts.append("Analysis instructions:\n" + body)
        return "\n\n".join(parts)

    def _flag_format_regex(self) -> str | None:
        value = self.flag_format_var.get().strip()
        if not value:
            return None
        if "\\" in value or "[" in value or "(" in value:
            return value
        if "{" in value and "}" in value:
            prefix = value.split("{", 1)[0]
            if prefix:
                return re.escape(prefix) + r"\{[A-Za-z0-9_@!#$%^&*()+\-=:;,.?/]{1,200}\}"
        return None

    def start_scan(self) -> None:
        target = self.input_var.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "분석할 파일, 폴더, 또는 텍스트를 입력하세요.")
            return
        self.status_var.set("Scanning...")
        self._set_buttons_state(tk.DISABLED)
        thread = threading.Thread(target=self._scan_worker, args=(target,), daemon=True)
        thread.start()

    def _scan_worker(self, target_input: str) -> None:
        try:
            report = self._build_scan_report(target_input)
            self.after(0, lambda: self._display(report))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Scan failed", str(exc)))
            self.after(0, lambda: self.status_var.set("Scan failed"))
        finally:
            self.after(0, lambda: self._set_buttons_state(tk.NORMAL))

    def _build_scan_report(self, target_input: str) -> dict[str, object]:
        prompt = self._structured_prompt()
        extra_patterns = [self.flag_var.get().strip()] if self.flag_var.get().strip() else []
        format_regex = self._flag_format_regex()
        if format_regex:
            extra_patterns.append(format_regex)
        raw_targets = read_targets(target_input)
        targets = [Target(label=label, data=data, path=path) for label, data, path in raw_targets]
        engine = SolverEngine(flag_patterns=DEFAULT_FLAG_PATTERNS + extra_patterns, prompt=prompt)
        findings = engine.analyze(targets)
        return {
            "version": __version__,
            "targets": [target.label for target in targets],
            "challenge_name": self.challenge_name_var.get().strip(),
            "flag_format": self.flag_format_var.get().strip(),
            "challenge_description": self.description_text.get("1.0", tk.END).strip(),
            "prompt_context": engine.prompt_context.as_dict(),
            "findings": [finding.as_dict() for finding in findings],
        }

    def _display(self, report: dict[str, object]) -> None:
        self.report = report
        self.tree.delete(*self.tree.get_children())
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            self.tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    finding.get("score", ""),
                    finding.get("category", ""),
                    finding.get("title", ""),
                    finding.get("value", "") or "",
                    finding.get("source", ""),
                ),
            )
        self.status_var.set(f"Done: {len(findings)} findings")
        if findings:
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
            self.show_selected()

    def start_ai_analysis(self) -> None:
        if not self.report:
            messagebox.showinfo("No report", "Run Scan first, or use Solve with AI.")
            return
        self.status_var.set("AI analyzing...")
        self._set_buttons_state(tk.DISABLED)
        thread = threading.Thread(target=self._ai_worker, daemon=True)
        thread.start()

    def start_solve_with_ai(self) -> None:
        target = self.input_var.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Select a file/folder first.")
            return
        self.status_var.set("Scanning, then AI analyzing...")
        self._set_buttons_state(tk.DISABLED)
        thread = threading.Thread(target=self._solve_with_ai_worker, args=(target,), daemon=True)
        thread.start()

    def _solve_with_ai_worker(self, target_input: str) -> None:
        try:
            report = self._build_scan_report(target_input)
            self.after(0, lambda: self._display(report))
            result = ask_openai(
                api_key=self.api_key_var.get(),
                model=self.model_var.get(),
                report=report,
                user_prompt=self._structured_prompt(),
                provider=self.provider_var.get(),
                api_mode=self.api_mode_var.get(),
                base_url=self.base_url_var.get(),
            )
            self.after(0, lambda: self._show_ai_result(result))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Solve with AI failed", str(exc)))
            self.after(0, lambda: self.status_var.set("Solve with AI failed"))
        finally:
            self.after(0, lambda: self._set_buttons_state(tk.NORMAL))

    def _ai_worker(self) -> None:
        try:
            result = ask_openai(
                api_key=self.api_key_var.get(),
                model=self.model_var.get(),
                report=self.report or {},
                user_prompt=self._structured_prompt(),
                provider=self.provider_var.get(),
                api_mode=self.api_mode_var.get(),
                base_url=self.base_url_var.get(),
            )
            self.after(0, lambda: self._show_ai_result(result))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("AI analysis failed", str(exc)))
            self.after(0, lambda: self.status_var.set("AI analysis failed"))
        finally:
            self.after(0, lambda: self._set_buttons_state(tk.NORMAL))

    def _show_ai_result(self, result: str) -> None:
        self.ai_result_text.configure(state=tk.NORMAL)
        self.ai_result_text.delete("1.0", tk.END)
        self.ai_result_text.insert("1.0", result)
        self.ai_result_text.configure(state=tk.DISABLED)
        self.notebook.select(3)
        self.status_var.set("AI analysis done")

    def show_selected(self, _event: object | None = None) -> None:
        if not self.report:
            return
        selection = self.tree.selection()
        if not selection:
            return
        findings = self.report.get("findings", [])
        if not isinstance(findings, list):
            return
        finding = findings[int(selection[0])]
        text = json.dumps(finding, indent=2, ensure_ascii=False)
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state=tk.DISABLED)

    def save_json(self) -> None:
        if not self.report:
            messagebox.showinfo("No report", "저장할 분석 결과가 없습니다.")
            return
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
        )
        if path:
            Path(path).write_text(json.dumps(self.report, indent=2, ensure_ascii=False), encoding="utf-8")
            self.status_var.set(f"Saved: {path}")

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.configure(state=tk.DISABLED)
        self.ai_result_text.configure(state=tk.NORMAL)
        self.ai_result_text.delete("1.0", tk.END)
        self.ai_result_text.configure(state=tk.DISABLED)
        self.report = None
        self.status_var.set("Ready")

    def _set_buttons_state(self, state: str) -> None:
        for child in self.winfo_children():
            self._walk_state(child, state)

    def _walk_state(self, widget: tk.Widget, state: str) -> None:
        if isinstance(widget, ttk.Button):
            widget.configure(state=state)
        for child in widget.winfo_children():
            self._walk_state(child, state)


def main() -> int:
    app = CtfBotGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
