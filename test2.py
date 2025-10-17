import tkinter as tk

class AnimatedBallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Animated Ball")
        
        # Create a canvas
        self.canvas = tk.Canvas(root, width=400, height=300, bg="white")
        self.canvas.pack(pady=20)
        
        # Create a red ball on the canvas
        self.ball = self.canvas.create_oval(50, 150, 80, 180, fill="red")
        
        # Initialize ball movement
        self.dx = 5  # Speed in x direction
        self.animate()
    
    def animate(self):
        # Move the ball
        self.canvas.move(self.ball, self.dx, 0)
        
        # Get current position of the ball
        pos = self.canvas.coords(self.ball)
        
        # Check if ball reaches the right edge of the canvas
        if pos[2] >= 400:  # pos[2] is the right x-coordinate
            self.canvas.coords(self.ball, 50, 150, 80, 180)  # Reset to starting position
        
        # Schedule the next animation frame
        self.root.after(50, self.animate)  # Update every 50ms

# Create and run the Tkinter application
if __name__ == "__main__":
    root = tk.Tk()
    app = AnimatedBallApp(root)
    root.mainloop()