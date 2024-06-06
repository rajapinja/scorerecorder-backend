#To get roundNumber - used in Dynamic Scores API
def get_max_roundNumber(db):

    cursor = db.cursor()
    cursor.execute("SELECT max(round_number) FROM record_scores")
    result = cursor.fetchone()  
    cursor.close()

    if result is not None and result[0] is not None:
        max_round_number = result[0]
        return max_round_number
    else:
        return 0
    
