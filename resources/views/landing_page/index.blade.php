<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" data-theme="black">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name', 'GymManager') }} - Elevate Your Fitness</title>

    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">

    <!-- DaisyUI & Tailwind CSS -->
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>

    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>

    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                    },
                    colors: {
                        odoo: {
                            primary: '#FACC15', // Yellow
                            secondary: '#FFFFFF', // White
                            accent: '#FEF08A', // Light Yellow
                            dark: '#FFFFFF', // White text for dark bg
                            light: '#18181B', // Zinc 900
                        }
                    }
                }
            }
        }
    </script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #000000;
            color: #ffffff;
        }
        .blob-shape {
            position: absolute;
            z-index: -1;
            opacity: 0.1;
        }
    </style>
</head>
<body class="flex flex-col min-h-screen">

    <!-- Navbar -->
    <div class="navbar bg-black container mx-auto px-4 py-4 sticky top-0 z-50 bg-opacity-90 backdrop-blur border-b border-zinc-800">
        <div class="navbar-start">
            <div class="dropdown">
                <div tabindex="0" role="button" class="btn btn-ghost lg:hidden text-white">
                    <i data-lucide="menu" class="w-6 h-6"></i>
                </div>
                <ul tabindex="0" class="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-zinc-900 rounded-box w-52 text-white">
                    <li><a href="#">Home</a></li>
                    <li><a href="#features">Features</a></li>
                    <li><a href="#classes">Classes</a></li>
                    <li><a href="#pricing">Pricing</a></li>
                </ul>
            </div>
            <a class="btn btn-ghost text-2xl font-bold text-odoo-primary gap-2">
                <i data-lucide="dumbbell" class="w-8 h-8 text-white"></i>
                GymManager
            </a>
        </div>
        <div class="navbar-center hidden lg:flex">
            <ul class="menu menu-horizontal px-1 text-base font-medium text-gray-300">
                <li><a href="#" class="hover:text-odoo-primary">Home</a></li>
                <li><a href="#features" class="hover:text-odoo-primary">Features</a></li>
                <li><a href="#classes" class="hover:text-odoo-primary">Classes</a></li>
                <li><a href="#pricing" class="hover:text-odoo-primary">Pricing</a></li>
            </ul>
        </div>
        <div class="navbar-end gap-2">
            @if (Route::has('login'))
                @auth
                    <a href="{{ url('/dashboard') }}" class="btn btn-sm btn-outline btn-primary">Dashboard</a>
                @else
                    <a href="{{ route('login') }}" class="btn btn-sm btn-ghost text-white hover:text-odoo-primary">Log in</a>
                    @if (Route::has('register'))
                        <a href="{{ route('register') }}" class="btn btn-sm bg-odoo-primary hover:bg-yellow-400 text-black border-none font-bold">Sign up</a>
                    @endif
                @endauth
            @endif
        </div>
    </div>

    <!-- Hero Section -->
    <section class="relative py-20 lg:py-32 overflow-hidden bg-black">
        <div class="container mx-auto px-4 flex flex-col-reverse lg:flex-row items-center gap-12">
            <!-- Text Content -->
            <div class="flex-1 text-center lg:text-left z-10">
                <h1 class="text-5xl lg:text-7xl font-bold leading-tight text-white mb-6">
                    Manage Your Gym <br>
                    <span class="text-odoo-primary">Like a Pro</span>
                </h1>
                <p class="text-lg text-gray-400 mb-8 max-w-lg mx-auto lg:mx-0">
                    The all-in-one platform to streamline your fitness business. 
                    Schedule classes, manage members, and track progress effortlessly.
                </p>
                <div class="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
                    <a href="{{ route('register') }}" class="btn btn-lg bg-odoo-primary hover:bg-yellow-400 text-black border-none shadow-lg font-bold">
                        Start Free Trial
                        <i data-lucide="arrow-right" class="w-5 h-5 ml-2"></i>
                    </a>
                    <a href="#features" class="btn btn-lg btn-ghost border-zinc-700 text-white hover:bg-zinc-800">
                        Learn More
                    </a>
                </div>
                <div class="mt-8 flex items-center justify-center lg:justify-start gap-4 text-sm text-gray-500">
                    <div class="flex items-center gap-1">
                        <i data-lucide="check-circle" class="w-4 h-4 text-odoo-primary"></i> No credit card required
                    </div>
                    <div class="flex items-center gap-1">
                        <i data-lucide="check-circle" class="w-4 h-4 text-odoo-primary"></i> 14-day free trial
                    </div>
                </div>
            </div>

            <!-- SVG Illustration -->
            <div class="flex-1 relative z-10">
                <!-- Abstract Gym Illustration -->
                <svg viewBox="0 0 600 500" xmlns="http://www.w3.org/2000/svg" class="w-full h-auto drop-shadow-2xl">
                    <defs>
                        <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:#FACC15;stop-opacity:1" />
                            <stop offset="100%" style="stop-color:#000000;stop-opacity:1" />
                        </linearGradient>
                    </defs>
                    <!-- Background Blob -->
                    <path fill="#18181B" d="M45.7,-76.3C58.9,-69.3,69.1,-55.6,76.3,-41.2C83.5,-26.8,87.7,-11.7,85.6,2.5C83.5,16.7,75.1,30,65.3,41.2C55.5,52.4,44.3,61.5,31.8,68.3C19.3,75.1,5.5,79.6,-7.1,77.8C-19.7,76,-31.1,67.9,-41.8,59.1C-52.5,50.3,-62.5,40.8,-69.8,29.1C-77.1,17.4,-81.7,3.5,-79.6,-9.4C-77.5,-22.3,-68.7,-34.2,-58.2,-43.5C-47.7,-52.8,-35.5,-59.5,-23.2,-67.1C-10.9,-74.7,1.5,-83.2,14.8,-84.2C28.1,-85.2,42.3,-78.7,45.7,-76.3Z" transform="translate(300 250) scale(3.5)" />
                    
                    <!-- Dashboard UI Mockup -->
                    <rect x="100" y="100" width="400" height="300" rx="10" fill="#27272A" stroke="#3F3F46" stroke-width="2" />
                    <rect x="100" y="100" width="400" height="40" rx="10" fill="#18181B" />
                    <circle cx="120" cy="120" r="5" fill="#ef4444" />
                    <circle cx="140" cy="120" r="5" fill="#f59e0b" />
                    <circle cx="160" cy="120" r="5" fill="#22c55e" />
                    
                    <!-- Chart -->
                    <path d="M140 350 L140 200 L200 250 L260 180 L320 280 L380 150 L440 350 Z" fill="url(#grad1)" opacity="0.2" />
                    <path d="M140 350 L140 200 L200 250 L260 180 L320 280 L380 150 L440 350" stroke="url(#grad1)" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round" />
                    
                    <!-- Floating Elements -->
                    <g transform="translate(420, 80)">
                        <rect width="120" height="80" rx="8" fill="#27272A" stroke="#3F3F46" stroke-width="1" class="drop-shadow-lg" />
                        <text x="60" y="30" font-family="sans-serif" font-size="12" text-anchor="middle" fill="#9CA3AF">Active Members</text>
                        <text x="60" y="60" font-family="sans-serif" font-size="24" font-weight="bold" text-anchor="middle" fill="#FACC15">1,240</text>
                    </g>

                    <g transform="translate(60, 280)">
                        <rect width="100" height="100" rx="8" fill="#27272A" stroke="#3F3F46" stroke-width="1" class="drop-shadow-lg" />
                        <circle cx="50" cy="40" r="20" fill="#FACC15" opacity="0.2" />
                        <path d="M50 30 L50 50 M40 40 L60 40" stroke="#FACC15" stroke-width="3" stroke-linecap="round" />
                        <text x="50" y="80" font-family="sans-serif" font-size="12" text-anchor="middle" fill="#D1D5DB">New Class</text>
                    </g>
                </svg>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section id="features" class="py-20 bg-zinc-900">
        <div class="container mx-auto px-4">
            <div class="text-center mb-16">
                <h2 class="text-3xl lg:text-4xl font-bold text-white mb-4">Everything You Need</h2>
                <p class="text-gray-400 max-w-2xl mx-auto">
                    Powerful features designed to help you run your gym smoothly and efficiently.
                </p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <!-- Feature 1 -->
                <div class="card bg-zinc-800 shadow-xl hover:shadow-2xl transition-shadow duration-300 border border-zinc-700">
                    <div class="card-body">
                        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-odoo-primary">
                            <i data-lucide="calendar-days" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Smart Scheduling</h3>
                        <p class="text-gray-400">Manage class schedules, trainer availability, and room bookings in one place.</p>
                        <!-- Functionality Placeholder -->
                        <div class="badge badge-outline text-gray-400 mt-4 text-xs">Backend: ScheduleController</div>
                    </div>
                </div>

                <!-- Feature 2 -->
                <div class="card bg-zinc-800 shadow-xl hover:shadow-2xl transition-shadow duration-300 border border-zinc-700">
                    <div class="card-body">
                        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-odoo-primary">
                            <i data-lucide="users" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Member Management</h3>
                        <p class="text-gray-400">Track memberships, attendance, and payments with detailed member profiles.</p>
                        <!-- Functionality Placeholder -->
                        <div class="badge badge-outline text-gray-400 mt-4 text-xs">Backend: MemberController</div>
                    </div>
                </div>

                <!-- Feature 3 -->
                <div class="card bg-zinc-800 shadow-xl hover:shadow-2xl transition-shadow duration-300 border border-zinc-700">
                    <div class="card-body">
                        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-odoo-primary">
                            <i data-lucide="activity" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Performance Tracking</h3>
                        <p class="text-gray-400">Let members track their workouts, weight, and progress over time.</p>
                        <!-- Functionality Placeholder -->
                        <div class="badge badge-outline text-gray-400 mt-4 text-xs">Backend: ProgressController</div>
                    </div>
                </div>

                <!-- Feature 4 -->
                <div class="card bg-zinc-800 shadow-xl hover:shadow-2xl transition-shadow duration-300 border border-zinc-700">
                    <div class="card-body">
                        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-odoo-primary">
                            <i data-lucide="credit-card" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Billing & Payments</h3>
                        <p class="text-gray-400">Automated billing, invoicing, and payment processing integration.</p>
                        <!-- Functionality Placeholder -->
                        <div class="badge badge-outline text-gray-400 mt-4 text-xs">Backend: PaymentController</div>
                    </div>
                </div>

                <!-- Feature 5 -->
                <div class="card bg-zinc-800 shadow-xl hover:shadow-2xl transition-shadow duration-300 border border-zinc-700">
                    <div class="card-body">
                        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-odoo-primary">
                            <i data-lucide="smartphone" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Mobile App</h3>
                        <p class="text-gray-400">Give members access to bookings and workouts on the go.</p>
                        <!-- Functionality Placeholder -->
                        <div class="badge badge-outline text-gray-400 mt-4 text-xs">API: Mobile Routes</div>
                    </div>
                </div>

                <!-- Feature 6 -->
                <div class="card bg-zinc-800 shadow-xl hover:shadow-2xl transition-shadow duration-300 border border-zinc-700">
                    <div class="card-body">
                        <div class="w-12 h-12 rounded-lg bg-zinc-700 flex items-center justify-center mb-4 text-odoo-primary">
                            <i data-lucide="message-circle" class="w-6 h-6"></i>
                        </div>
                        <h3 class="card-title text-white">Communication</h3>
                        <p class="text-gray-400">Built-in messaging and notifications to keep your community engaged.</p>
                        <!-- Functionality Placeholder -->
                        <div class="badge badge-outline text-gray-400 mt-4 text-xs">Backend: NotificationSystem</div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Classes Preview Section -->
    <section id="classes" class="py-20 bg-black">
        <div class="container mx-auto px-4">
            <div class="flex flex-col lg:flex-row justify-between items-end mb-12">
                <div class="max-w-2xl">
                    <h2 class="text-3xl lg:text-4xl font-bold text-white mb-4">Popular Classes</h2>
                    <p class="text-gray-400">Join our community and find the perfect class for your fitness journey.</p>
                </div>
                <a href="#" class="btn btn-link text-odoo-primary no-underline hover:text-yellow-300 mt-4 lg:mt-0">
                    View All Classes <i data-lucide="arrow-right" class="w-4 h-4"></i>
                </a>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Class Card 1 -->
                <div class="card bg-zinc-900 shadow-lg image-full before:!bg-opacity-40 hover:before:!bg-opacity-30 transition-all cursor-pointer group border border-zinc-800">
                    <figure>
                        <!-- SVG Pattern Background instead of Image -->
                        <svg class="w-full h-64 bg-zinc-800" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
                            <defs>
                                <pattern id="pattern-yoga" x="0" y="0" width="40" height="40" patternUnits="userSpaceOnUse">
                                    <circle cx="20" cy="20" r="2" fill="#FACC15" opacity="0.3"/>
                                </pattern>
                            </defs>
                            <rect width="100%" height="100%" fill="#18181B"/>
                            <rect width="100%" height="100%" fill="url(#pattern-yoga)"/>
                            <path d="M0 200 Q 150 100 300 200 T 600 200" stroke="#FACC15" stroke-width="2" fill="none" opacity="0.2"/>
                        </svg>
                    </figure>
                    <div class="card-body justify-end">
                        <h2 class="card-title text-white text-2xl">Yoga Flow</h2>
                        <p class="text-gray-300 flex-grow-0">Find your balance and inner peace.</p>
                        <div class="card-actions justify-end mt-4">
                            <button class="btn btn-sm bg-odoo-primary text-black border-none hover:bg-yellow-300">Book Now</button>
                        </div>
                    </div>
                </div>

                <!-- Class Card 2 -->
                <div class="card bg-zinc-900 shadow-lg image-full before:!bg-opacity-40 hover:before:!bg-opacity-30 transition-all cursor-pointer group border border-zinc-800">
                    <figure>
                        <svg class="w-full h-64 bg-zinc-800" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
                            <defs>
                                <pattern id="pattern-hiit" x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
                                    <path d="M0 20 L20 0" stroke="#FACC15" stroke-width="1" opacity="0.2"/>
                                </pattern>
                            </defs>
                            <rect width="100%" height="100%" fill="#18181B"/>
                            <rect width="100%" height="100%" fill="url(#pattern-hiit)"/>
                            <circle cx="300" cy="100" r="80" fill="#FACC15" opacity="0.1"/>
                        </svg>
                    </figure>
                    <div class="card-body justify-end">
                        <h2 class="card-title text-white text-2xl">HIIT Blast</h2>
                        <p class="text-gray-300 flex-grow-0">High intensity training for maximum burn.</p>
                        <div class="card-actions justify-end mt-4">
                            <button class="btn btn-sm bg-odoo-primary text-black border-none hover:bg-yellow-300">Book Now</button>
                        </div>
                    </div>
                </div>

                <!-- Class Card 3 -->
                <div class="card bg-zinc-900 shadow-lg image-full before:!bg-opacity-40 hover:before:!bg-opacity-30 transition-all cursor-pointer group border border-zinc-800">
                    <figure>
                        <svg class="w-full h-64 bg-zinc-800" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
                            <defs>
                                <pattern id="pattern-strength" x="0" y="0" width="50" height="50" patternUnits="userSpaceOnUse">
                                    <rect x="0" y="0" width="25" height="25" fill="#FACC15" opacity="0.1"/>
                                </pattern>
                            </defs>
                            <rect width="100%" height="100%" fill="#18181B"/>
                            <rect width="100%" height="100%" fill="url(#pattern-strength)"/>
                        </svg>
                    </figure>
                    <div class="card-body justify-end">
                        <h2 class="card-title text-white text-2xl">Power Lifting</h2>
                        <p class="text-gray-300 flex-grow-0">Build strength and muscle mass.</p>
                        <div class="card-actions justify-end mt-4">
                            <button class="btn btn-sm bg-odoo-primary text-black border-none hover:bg-yellow-300">Book Now</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="py-20 bg-odoo-primary text-black relative overflow-hidden">
        <!-- Decorative Circles -->
        <div class="absolute top-0 left-0 -ml-20 -mt-20 w-64 h-64 rounded-full bg-black opacity-10"></div>
        <div class="absolute bottom-0 right-0 -mr-20 -mb-20 w-80 h-80 rounded-full bg-white opacity-20"></div>

        <div class="container mx-auto px-4 text-center relative z-10">
            <h2 class="text-3xl lg:text-5xl font-bold mb-6">Ready to Transform Your Gym?</h2>
            <p class="text-xl text-zinc-800 mb-10 max-w-2xl mx-auto">
                Join thousands of gym owners who trust GymManager to run their business.
            </p>
            <div class="flex flex-col sm:flex-row gap-4 justify-center">
                <a href="{{ route('register') }}" class="btn btn-lg bg-black text-white hover:bg-zinc-800 border-none">
                    Get Started Now
                </a>
                <a href="#" class="btn btn-lg btn-outline text-black border-black hover:bg-black hover:text-white">
                    Contact Sales
                </a>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer p-10 bg-zinc-900 text-gray-400">
        <aside>
            <div class="flex items-center gap-2 mb-4">
                <div class="bg-odoo-primary p-2 rounded-lg text-black">
                    <i data-lucide="dumbbell" class="w-6 h-6"></i>
                </div>
                <span class="font-bold text-xl text-white">GymManager</span>
            </div>
            <p>GymManager Industries Ltd.<br/>Providing reliable tech since 2025</p>
        </aside> 
        <nav>
            <h6 class="footer-title text-white opacity-100">Services</h6> 
            <a class="link link-hover">Branding</a>
            <a class="link link-hover">Design</a>
            <a class="link link-hover">Marketing</a>
            <a class="link link-hover">Advertisement</a>
        </nav> 
        <nav>
            <h6 class="footer-title text-white opacity-100">Company</h6> 
            <a class="link link-hover">About us</a>
            <a class="link link-hover">Contact</a>
            <a class="link link-hover">Jobs</a>
            <a class="link link-hover">Press kit</a>
        </nav> 
        <nav>
            <h6 class="footer-title text-white opacity-100">Legal</h6> 
            <a class="link link-hover">Terms of use</a>
            <a class="link link-hover">Privacy policy</a>
            <a class="link link-hover">Cookie policy</a>
        </nav>
    </footer>

    <script>
        // Initialize Lucide Icons
        lucide.createIcons();
    </script>
</body>
</html>
