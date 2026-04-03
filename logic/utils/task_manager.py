import concurrent.futures
import threading

class TaskManager:
    """
    Gestore centralizzato per i task asincroni del toolkit.
    Gestisce un pool di thread e permette l'interruzione dei task.
    """
    def __init__(self, max_workers=100):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks = {} # task_id -> (future, stop_event)
        self._lock = threading.Lock()

    def start_task(self, task_id, func, *args, **kwargs):
        """
        Avvia un nuovo task asincrono con un id unico.
        """
        with self._lock:
            # Se esiste già un task con questo ID, lo fermiamo prima
            if task_id in self.active_tasks:
                self.stop_task(task_id)
            
            stop_event = threading.Event()
            # Passiamo l'event alla funzione come parametro speciale se lo supporta
            # La funzione deve accettare un parametro 'stop_event'
            future = self.executor.submit(func, *args, stop_event=stop_event, **kwargs)
            self.active_tasks[task_id] = (future, stop_event)
            
            # Quando il task finisce, lo rimuoviamo dalla lista degli attivi
            future.add_done_callback(lambda f: self._cleanup_task(task_id))
            return future

    def stop_task(self, task_id):
        """
        Invia un segnale di stop al task e tenta di cancellarlo.
        """
        with self._lock:
            if task_id in self.active_tasks:
                future, stop_event = self.active_tasks[task_id]
                stop_event.set()
                future.cancel() # Tenta la cancellazione (funziona solo se non è ancora partito)
                return True
        return False

    def is_running(self, task_id):
        """
        Verifica se un task è attualmente attivo (in coda o in esecuzione).
        """
        with self._lock:
            return task_id in self.active_tasks

    def _cleanup_task(self, task_id):
        """
        Rimuove il task dagli attivi quando termina.
        """
        with self._lock:
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]

    def shutdown(self):
        """
        Spegne l'executor e ferma tutti i task pendenti.
        """
        with self._lock:
            for _, stop_event in self.active_tasks.values():
                stop_event.set()
        self.executor.shutdown(wait=False)
