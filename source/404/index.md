---
title: '404 - 真巧，竟然在這裡遇到你！比巧克力還巧欸!!!'
date: 2020-09-12 23:01:35
comments: true
permalink: /404.html
---

<!-- markdownlint-disable MD039 MD033 -->

## 這是一個不存在的頁面

Sorry, the page you are currently accessing does not exist.

Expect to return to the home page in <span id="timeout">5</span> seconds.

**[home page](https://KzcDuD.github.com)** 

<script>
let countTime = 5;

function count() {
  
  document.getElementById('timeout').textContent = countTime;
  countTime -= 1;
  if(countTime === 0){
    location.href = 'https://KzcDuD.github.com'; // 記得改成自己網址 Url
  }
  setTimeout(() => {
    count();
  }, 1000);
}

count();
</script>