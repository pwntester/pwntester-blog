+++
author = "pwntester"
categories = ["polictf2015"]
date = 2015-07-12T09:55:35Z
description = ""
draft = false
slug = "picoctf-web100"
tags = ["polictf2015"]
title = "PoliCTF 2015. Web100 - John The Traveller"

+++

> Holidays are here! 
> But John still hasn't decided where to spend them and time is running out: flights are overbooked and prices are rising every second. 
> Fortunately, John just discovered a website where he can book last second flight to all the European capitals; 
> however, there's no time to waste, so he just grabs his suitcase and thanks to his new smartphone he looks the city of his choice up while rushing to the airport. 
> There he goes! Flight is booked so... hauskaa lomaa! 
![](/images/2015/07/Screen-Shot-2015-07-11-at-16-38-32.png)
We are presented with a web that allows us to search for European capitals. It does seem injectable and theres nothing weird. The website returns a random number of flights with their costs in EURs and nothing else.

After losing a lot of time with this one, we re-read the challange description once again and wondered about `hauskaa lomaa`. It turns out it means `Happy vacations` in Finish. So we checked flights to Helsinki and finally something out of the ordinary: the price was in `px` (pixels?) and there where always 6 results:
![](/images/2015/07/Screen-Shot-2015-07-11-at-16-43-10.png)

After having a look at the source code we realize that it contains a responsive UI and that the result table contains special classes:
![](/images/2015/07/Screen-Shot-2015-07-11-at-16-44-25.png)
![](/images/2015/07/Screen-Shot-2015-07-11-at-16-45-02.png)

After loading the page on a device emulator with any of those widths, we get a QR:
![](/images/2015/07/Screen-Shot-2015-07-11-at-16-46-22.png)

Flag is: `flag{run_to_the_hills_run_for_your_life}`
