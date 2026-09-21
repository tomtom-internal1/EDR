# KDASA Evidence Query

The query helper reads the local SQLite evidence store created by kdasa_db.py. It is deliberately offline.

Examples:

    python tools/kdasa_query.py out\\evidence.db --type ProcessStart
    python tools/kdasa_query.py out\\evidence.db --pid 1200 --limit 50
    python tools/kdasa_query.py out\\evidence.db --source etw --run-id 3
