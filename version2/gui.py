import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu
import threading
import logic  # nuestro módulo de lógica

# Inicializar gateway
logic.init_gateway()

# --- GUI: ventana de ARP Spoofing (secundaria) ---
def abrir_ventana_spoof():
    spoof_win = tk.Toplevel(ventana)
    spoof_win.title("ARP Spoofing")
    spoof_win.geometry("450x300")

    frame2 = ttk.Frame(spoof_win, padding=10)
    frame2.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame2, text="IP Objetivo:").grid(row=0, column=0, sticky=tk.W)
    entry_spoof = ttk.Entry(frame2, width=25)
    entry_spoof.grid(row=0, column=1, padx=5)
    ttk.Button(
        frame2,
        text="Copiar IP",
        command=lambda: (
            spoof_win.clipboard_clear(),
            spoof_win.clipboard_append(entry_spoof.get().strip()),
            messagebox.showinfo("Copiar IP", "IP copiada.")
        )
    ).grid(row=0, column=2)

    log2 = scrolledtext.ScrolledText(frame2, width=50, height=10)
    log2.grid(row=2, column=0, columnspan=3, pady=10)

    def start_spoof():
        ip = entry_spoof.get().strip()
        if ip:
            logic.start_spoof(ip, lambda msg: log2.insert(tk.END, msg) or log2.see(tk.END))
        else:
            messagebox.showwarning("Aviso", "Ingrese IP objetivo.")

    def stop_spoof():
        logic.stop_spoof()
        log2.insert(tk.END, "Spoofing detenido.\n")
        log2.see(tk.END)

    ttk.Button(frame2, text="Iniciar Spoof", command=start_spoof).grid(row=1, column=1, pady=5)
    ttk.Button(frame2, text="Detener Spoof", command=stop_spoof).grid(row=1, column=2)

# --- GUI Principal: ventana de escaneo ---
ventana = tk.Tk()
ventana.title("Escaneo de Red - Herramienta ARP Avanzada")
ventana.geometry("600x400")

# Menú
menubar = Menu(ventana)
menu_ops = Menu(menubar, tearoff=0)
menu_ops.add_command(label="ARP Spoofing", command=abrir_ventana_spoof)
menubar.add_cascade(label="Opciones", menu=menu_ops)
ventana.config(menu=menubar)

# Frame principal de escaneo
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

btn_frame = ttk.Frame(frame)
btn_frame.pack(pady=5)

# Botón iniciar escaneo: crea y arranca hilo correctamente
def iniciar_scan():
    thread = threading.Thread(
        target=logic.scan_network,
        args=(
            "192.168.1.0/24",
            lambda ip, mac, hn, v: tree.insert('', tk.END, values=(ip, mac, hn, v)),
            lambda s: status.config(text=f"Estado: {s}")
        ),
        daemon=True
    )
    thread.start()

ttk.Button(btn_frame, text="Iniciar Escaneo", command=iniciar_scan).pack(side=tk.LEFT, padx=5)
ttk.Button(btn_frame, text="Copiar IP", command=lambda: copiar_seleccion(tree, 0)).pack(side=tk.LEFT, padx=5)
ttk.Button(btn_frame, text="Copiar MAC", command=lambda: copiar_seleccion(tree, 1)).pack(side=tk.LEFT, padx=5)

# Función para copiar selección
def copiar_seleccion(tree, col_index):
    sel = tree.selection()
    if sel:
        val = tree.item(sel[0])['values'][col_index]
        ventana.clipboard_clear()
        ventana.clipboard_append(val)
        messagebox.showinfo("Copiar", f"'{val}' copiado.")
    else:
        messagebox.showwarning("Aviso", "Seleccione un elemento.")

ventana.mainloop()
