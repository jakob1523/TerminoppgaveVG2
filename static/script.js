let score = 0;
let high_score = 0;
let botValg = 0;
let userValg = 0;

const csrfToken = document.getElementById('csrf_token').value;

function botChoice() {
    let botValg = Math.floor(Math.random() * 3) + 1;
    const imageElement = document.getElementById('botBilde');
    const noe = document.getElementById('scoree');
    const high_noe = document.getElementById('high_score');
    const resu_noe = document.getElementById('resultat');

    if (botValg === 1) {
        console.log("Bot valgte stein");
        imageElement.src = 'static/bilder/rock.png';
    }
    else if (botValg === 2) {
        console.log("Bot valgte papir");
        imageElement.src = 'static/bilder/paper.png';
    }
    else {
        console.log("Bot valgte saks");
        imageElement.src = 'static/bilder/scissor.png';
    }
   
    if ((userValg === 1 && botValg === 1) || (userValg === 2 && botValg === 2) || (userValg === 3 && botValg === 3)) {
        console.log("det er likt");
        resu_noe.textContent = 'Det er likt.';
    }
   
    else if ((userValg === 1 && botValg === 3) || (userValg === 2 && botValg === 1) || (userValg === 3 && botValg === 2)) {
        console.log("du vant");
        score++;
        
        if (high_score < score) {
            high_score = score;
            high_noe.textContent = "High score: " + high_score;
            saveHighScore(high_score);
        }
    
        noe.textContent = "Score: " + score;
        resu_noe.textContent = 'Du vant!';
    }
    
    else {
        console.log("du tapte womp womp");
        score = 0;
        noe.textContent = "Score: " + score;
        resu_noe.textContent = 'Du tapte.';
    }
}

function userChoice(ja) {
    const imageElement = document.getElementById('valgBilde');
    if (ja === "rock") {
        userValg = 1;
        console.log("Du valgte stein");
        imageElement.src = 'static/bilder/rock.png';        
    }
    else if (ja === "paper") {
        userValg = 2;
        console.log("Du valgte papir");
        imageElement.src = 'static/bilder/paper.png';
    }
    else {
        userValg = 3;
        console.log("Du valgte saks");
        imageElement.src = 'static/bilder/scissor.png';
    }
    botChoice();  
}

function saveHighScore(score) {
    fetch('/save_score', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            score: score
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Score saved:', data);
    })
    .catch(error => {
        console.error('Error saving score:', error);
    });
}
