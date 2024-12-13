document.addEventListener("DOMContentLoaded", function() {
    
    const csrfToken = document.getElementById('csrf_token').value;

    var blockSize = 25;
    var rows = 20;
    var cols = 20;
    var board;
    var context;
    let SnakeScore = 0;
    var scoree;

    // Snake head
    var snakeX = blockSize * 5;
    var snakeY = blockSize * 5;

    var velocityX = 0;
    var velocityY = 0;

    var snakeBody = [];

    // Food
    var foodX;
    var foodY;

    var gameOver = false;

    window.onload = function() {
        board = document.getElementById("board");
        board.height = rows * blockSize;
        board.width = cols * blockSize;
        context = board.getContext("2d"); 
        scoree = document.getElementById('snake-score'); 

        placeFood();

        document.addEventListener("keyup", changeDirection);
        setInterval(update, 1000 / 8); 

        
        document.addEventListener("keydown", (e) => {
            if (gameOver && e.code === "Enter") {
                resetGame();
            }
        });
    };

    function update() {
        if (gameOver) {
            context.fillStyle = "red";
            context.font = "40px Courier New";
            context.textAlign = "center";
            context.fillText("Game Over!", board.width / 2, board.height / 2);
            context.fillText("Press Enter to Replay", board.width / 2, board.height / 2 + 40);
            return;
        }

        context.fillStyle = "black";
        context.fillRect(0, 0, board.width, board.height);

        context.fillStyle = "red";
        context.fillRect(foodX, foodY, blockSize, blockSize);

        if (snakeX == foodX && snakeY == foodY) {
            snakeBody.push([foodX, foodY]);
            placeFood();
            SnakeScore++;
            console.log('wow, du fikk poeng')
            scoree.textContent = 'Score: ' + SnakeScore; // Update score display
            SaveSnakeScore(SnakeScore)
        }

        for (let i = snakeBody.length - 1; i > 0; i--) {
            snakeBody[i] = snakeBody[i - 1];
        }
        if (snakeBody.length) {
            snakeBody[0] = [snakeX, snakeY];
        }

        context.fillStyle = "lime";
        snakeX += velocityX * blockSize;
        snakeY += velocityY * blockSize;
        context.fillRect(snakeX, snakeY, blockSize, blockSize);
        for (let i = 0; i < snakeBody.length; i++) {
            context.fillRect(snakeBody[i][0], snakeBody[i][1], blockSize, blockSize);
        }

        // Game over conditions
        if (snakeX < 0 || snakeX >= cols * blockSize || snakeY < 0 || snakeY >= rows * blockSize) {
            gameOver = true;
        }

        for (let i = 0; i < snakeBody.length; i++) {
            if (snakeX == snakeBody[i][0] && snakeY == snakeBody[i][1]) {
                gameOver = true;
            }
        }
    }

    function changeDirection(e) {
        if (e.code == "ArrowUp" && velocityY != 1) {
            velocityX = 0;
            velocityY = -1;
        } else if (e.code == "ArrowDown" && velocityY != -1) {
            velocityX = 0;
            velocityY = 1;
        } else if (e.code == "ArrowLeft" && velocityX != 1) {
            velocityX = -1;
            velocityY = 0;
        } else if (e.code == "ArrowRight" && velocityX != -1) {
            velocityX = 1;
            velocityY = 0;
        }
    }

    function placeFood() {
        foodX = Math.floor(Math.random() * cols) * blockSize;
        foodY = Math.floor(Math.random() * rows) * blockSize;
    }

    function resetGame() {
        // Reset game variables
        snakeX = blockSize * 5;
        snakeY = blockSize * 5;
        velocityX = 0;
        velocityY = 0;
        snakeBody = [];
        SnakeScore = 0;
        scoree.textContent = 'Score: 0';
        gameOver = false;
        placeFood();
    }

    function SaveSnakeScore(score) {
        fetch('/snake_score', {
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

});
