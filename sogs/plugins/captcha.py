from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageDraw, ImageFont
from sogs.emoji_list import EMOJI_LIST
import math
import random
import time
import asyncio
import os

class Captcha:

    def __init__(self, answer, file_name):
        self.answer = answer
        self.file_name = file_name

    async def generate_captcha(self, executor, width, height):
        pass


class EmojiCaptcha(Captcha):
    class Shape:
        def __init__(self, type, color, x1, y1, x2, y2):
            self.type = type
            self.color = color
            self.x1 = x1
            self.y1 = y1
            self.x2 = x2
            self.y2 = y2

        def draw_shape(self, draw):
            if self.type == "rectangle":
                draw.rectangle(
                    [self.x1, self.y1, self.x2, self.y2],
                    fill=self.color
                )
            elif self.type == "hexagon":
                draw.regular_polygon(
                    [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2,
                     min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                    6,
                    fill=self.color
                )
            elif self.type == "circle":
                # Ensure the bounding box is square to draw a perfect circle
                side_length = min(self.x2 - self.x1, self.y2 - self.y1)
                x2 = self.x1 + side_length
                y2 = self.y1 + side_length
                draw.ellipse(
                    [self.x1, self.y1, x2, y2],
                    fill=self.color
                )
            elif self.type == "triangle":
                draw.regular_polygon(
                    [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2,
                     min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                    3,
                    fill=self.color
                )
            elif self.type == "star":
                # Parameters for star shape
                center_x = (self.x1 + self.x2) // 2
                center_y = (self.y1 + self.y2) // 2
                radius = min(self.x2 - self.x1, self.y2 - self.y1) // 2
                points = []

                for i in range(10):  # 5 points for a star, each point needs 2 coordinates (outer and inner)
                    angle = i * (2 * 3.14159 / 10)
                    r = radius if i % 2 == 0 else radius // 2
                    x = center_x + r * math.cos(angle)
                    y = center_y + r * math.sin(angle)
                    points.append((x, y))
                draw.polygon(points, fill=self.color)

            elif self.type == "octagon":
                draw.regular_polygon(
                    [(self.x1 + self.x2) // 2, (self.y1 + self.y2) // 2,
                     min(self.x2 - self.x1, self.y2 - self.y1) // 2],
                    8,
                    fill=self.color
                )

    FONT_PATH = 'NotoColorEmoji.ttf'
    # Bitmap fonts don't support scaling with freetype, so you must specify a valid size,
    # which is 109 for Noto Color Emoji.
    FONT_SIZE = 109
    WIDTH = 400
    HEIGHT = 400

    def __init__(self, answer_emoji, file_name):
        # List of possible shapes
        self.shape_set = ["rectangle", "hexagon", "circle", "triangle", "star", "octagon"]
        # List of primary colors
        self.color_set = ["#31F196", "#57C9FA", "#C993FF", "#FF95EF", "#FF9C8E", "#FCB159", "#FAD657"]

        Captcha.__init__(
            self,
            answer=answer_emoji,
            file_name=file_name
        )

    async def generate_captcha(self, executor, width=WIDTH, height=HEIGHT):
        # Create a new image with white background
        image = Image.new("RGB", (width, height), "#626262")
        draw = ImageDraw.Draw(image)

        # Precompute random colors
        random_colors = [random.choice(self.color_set) for _ in range(6)]
        shapes = []
        min_size_x = int(width * 0.3)
        min_size_y = int(height * 0.3)
        # Draw 6 shapes randomly on the image
        for shape_type in self.shape_set:
            color = random_colors[len(shapes)]
            x1 = random.randint(0, width - min_size_x)
            y1 = random.randint(0, height - min_size_y)
            x2 = x1 + random.randint(min_size_x, min(width - x1, int(width / 2)))
            y2 = y1 + random.randint(min_size_y, min(height - y1, int(height / 2)))
            shape = EmojiCaptcha.Shape(shape_type, color, x1, y1, x2, y2)
            shapes.append(shape)
            shape.draw_shape(draw)

        emoji_x = random.randint(0, width - EmojiCaptcha.FONT_SIZE)
        emoji_y = random.randint(0, height - EmojiCaptcha.FONT_SIZE)
        draw.text(
            (emoji_x, emoji_y),
            self.answer,
            font=ImageFont.truetype(EmojiCaptcha.FONT_PATH, EmojiCaptcha.FONT_SIZE, layout_engine=ImageFont.Layout.RAQM),
            embedded_color=True
        )
        # Save the image
        image_path = f"{self.file_name}"
        await asyncio.get_event_loop().run_in_executor(executor, image.save, image_path)


class CaptchaManager:

    IMAGES_DIR = "async_generated_images"

    def __init__(self, initial_count=200):
        self.captcha_list = []
        os.makedirs(CaptchaManager.IMAGES_DIR, exist_ok=True)
        start_time = time.time()
        asyncio.run(self.batch_generate_captcha(initial_count))
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time} seconds")

    async def batch_generate_captcha(self, count):
        tasks = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for i in range(count):
                captcha = EmojiCaptcha(
                    random.choice(list(EMOJI_LIST)),
                    f"{CaptchaManager.IMAGES_DIR}/shapes_image_{i}.png"
                )
                self.captcha_list.append(captcha)
                tasks.append(captcha.generate_captcha(executor))
            await asyncio.gather(*tasks)

    def refresh(self) -> Captcha:
        if len(self.captcha_list) == 0:
            asyncio.run(self.batch_generate_captcha(20))
        return self.captcha_list.pop()