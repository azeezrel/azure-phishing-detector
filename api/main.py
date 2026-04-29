@app.get("/metrics")
async def get_metrics():
    """MLOps: Model performance metrics"""
    metrics = {
        "model_version": model_metadata.get('model_version', '1.0.0'),
        "accuracy": model_metadata.get('accuracy', 0.75),
        "training_samples": model_metadata.get('training_samples', 0),
        "status": "healthy" if model is not None else "degraded_fallback"
    }

    if os.path.exists(FEEDBACK_FILE):
        try:
            with open(FEEDBACK_FILE, "r") as f:
                logs = [json.loads(line) for line in f]

            total = len(logs)
            blocked = sum(1 for log in logs if log.get('action') == 'BLOCK')

            metrics['total_scans'] = total
            metrics['blocked_count'] = blocked
            metrics['block_rate'] = round(blocked / total * 100, 2) if total > 0 else 0
            metrics['feedback_samples'] = total
        except Exception:  # Fixed: bare except -> Exception
            pass

    return metrics
