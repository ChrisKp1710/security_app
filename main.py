from gui.dashboard import Dashboard

def main():
    # In CustomTkinter, la classe Dashboard è essa stessa l'applicazione.
    # Non serve creare 'root = tk.Tk()' separatamente.
    app = Dashboard()
    app.mainloop()

if __name__ == "__main__":
    main()
