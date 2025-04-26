import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import logic

logic.init_gateway()

ventana = tk.Tk()
ventana.title("Escaneo de Red - Herramienta ARP Avanzada")
ventana.geometry("600x450")

def abrir_ventana_spoof():
    spoof_win = tk.Toplevel(ventana)
    spoof_win.title("ARP Spoofing")
    spoof_win.geometry("450x300")

    frame = ttk.Frame(spoof_win, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="IP Objetivo:").grid(row=0, column=0, sticky=tk.W)
    entry = ttk.Entry(frame, width=25)
    entry.grid(row=0, column=1, padx=5)

    ttk.Button(frame, text="Pegar del portapapeles", command=lambda: (
        entry.delete(0, tk.END),
        entry.insert(0, spoof_win.clipboard_get())
    )).grid(row=0, column=2)

    log = scrolledtext.ScrolledText(frame, width=50, height=10)
    log.grid(row=2, column=0, columnspan=3, pady=10)

    def start():
        ip = entry.get().strip()
        if ip:
            logic.start_spoof(ip, lambda msg: (log.insert(tk.END, msg), log.see(tk.END)))
        else:
            messagebox.showwarning("Advertencia", "Ingrese una IP objetivo.")

    def stop():
        logic.stop_spoof()
        log.insert(tk.END, "Spoofing detenido.\n")
        log.see(tk.END)

    ttk.Button(frame, text="Iniciar Spoof", command=start).grid(row=1, column=1, pady=5)
    ttk.Button(frame, text="Detener Spoof", command=stop).grid(row=1, column=2)

menubar = tk.Menu(ventana)
menu_ops = tk.Menu(menubar, tearoff=0)
menu_ops.add_command(label="ARP Spoofing", command=abrir_ventana_spoof)
menubar.add_cascade(label="Opciones", menu=menu_ops)
ventana.config(menu=menubar)

frame = ttk.Frame(ventana, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

cols = ("IP", "MAC", "Hostname", "Vendor")
tree = ttk.Treeview(frame, columns=cols, show='headings')
for c in cols:
    tree.heading(c, text=c)
    tree.column(c, width=140)
tree.pack(fill=tk.BOTH, expand=True)

status = ttk.Label(frame, text="Estado: Esperando...")
status.pack(fill=tk.X, pady=5)

progress = ttk.Progressbar(frame, orient='horizontal', length=400, mode='determinate')
progress.pack(pady=5)

btn_frame = ttk.Frame(frame)
btn_frame.pack(pady=5)

def iniciar_scan():
    for item in tree.get_children():
        tree.delete(item)
    progress['value'] = 0
    status.config(text="Estado: Preparado...")

    def update_row(ip, mac, hn, v):
        tree.insert('', tk.END, values=(ip, mac, hn, v))
    def update_status(s):
        status.config(text=s)
    def update_progress(count, total):
        progress['maximum'] = total
        progress['value'] = count

    threading.Thread(target=logic.scan_network,
                     args=("192.168.1.0/24", update_row, update_status, update_progress),
                     daemon=True).start()

def detener_scan():
    logic.stop_scan()
    status.config(text="Estado: Escaneo detenido.")

def copiar_seleccion(tree, col_index):
    sel = tree.selection()
    if sel:
        val = tree.item(sel[0])['values'][col_index]
        ventana.clipboard_clear()
        ventana.clipboard_append(val)
        messagebox.showinfo("Copiar", f"{val} copiado.")
    else:
        messagebox.showwarning("Aviso", "Seleccione un elemento.")

ttk.Button(btn_frame, text="Iniciar Escaneo", command=iniciar_scan).pack(side=tk.LEFT, padx=5)
ttk.Button(btn_frame, text="Detener Escaneo", command=detener_scan).pack(side=tk.LEFT, padx=5)
ttk.Button(btn_frame, text="Copiar IP", command=lambda: copiar_seleccion(tree, 0)).pack(side=tk.LEFT, padx=5)
ttk.Button(btn_frame, text="Copiar MAC", command=lambda: copiar_seleccion(tree, 1)).pack(side=tk.LEFT, padx=5)

ventana.mainloop()
