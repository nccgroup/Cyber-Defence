package Crypt
{
   import flash.utils.ByteArray;
   
   public final class Crypt
   {
       
      public function Crypt()
      {
         if(!_loc1_)
         {
            super();
         }
      }
      
      public static function xor(param1:ByteArray, param2:ByteArray) : ByteArray
      {
         §§push(0);
         if(_loc7_)
         {
            §§push(---(§§pop() * 4 - 1 - 103) - 86);
         }
         if(!_loc6_)
         {
            §§push(param2);
            §§push(0);
            if(_loc6_)
            {
               §§push(--(§§pop() * 90) - 43);
            }
            §§pop().position = §§pop();
            if(!_loc7_)
            {
               loop0:
               while(_loc5_ < param2.length)
               {
                  if(_loc6_)
                  {
                     loop1:
                     while(true)
                     {
                        §§push(_loc5_);
                        if(!_loc7_)
                        {
                           §§push(Number(§§pop()));
                           if(!_loc6_)
                           {
                              §§push(§§pop() + 1);
                           }
                           §§push(uint(§§pop()));
                        }
                        if(!_loc6_)
                        {
                           if(!_loc6_)
                           {
                              continue loop0;
                           }
                        }
                        addr119:
                        while(true)
                        {
                           if(_loc7_)
                           {
                              break loop1;
                           }
                           continue loop1;
                        }
                     }
                     continue;
                  }
                  while(true)
                  {
                     _loc3_.writeByte(param2.readByte() ^ param1[_loc5_ % _loc4_]);
                     §§goto(addr119);
                  }
               }
            }
         }
         if(!_loc7_)
         {
         }
         return _loc3_;
      }
      
      public static function rc4(param1:ByteArray, param2:String) : ByteArray
      {
         §§push(0);
         if(_loc10_)
         {
            §§push(§§pop() * 94 - 45 - 12 + 102 + 1);
         }
         §§push(0);
         if(_loc9_)
         {
            §§push((§§pop() + 1) * 55 + 17 + 1);
         }
         §§push(0);
         if(_loc10_)
         {
            §§push(-(§§pop() * 54 * 61 + 1 - 108 + 111));
         }
         var _loc7_:* = §§pop();
         var _loc5_:ByteArray = new ByteArray();
         §§push(0);
         if(_loc9_)
         {
            §§push(-§§pop() - 91 - 1);
         }
         var _loc3_:ByteArray = new ByteArray();
         §§push(0);
         if(_loc9_)
         {
            §§push(--((§§pop() - 108 + 1 + 1) * 30));
         }
         if(!_loc10_)
         {
            loop0:
            while(true)
            {
               §§push(_loc8_);
               if(!_loc9_)
               {
                  §§push(256);
                  if(_loc9_)
                  {
                     §§push(-(§§pop() + 63 + 51 + 22) - 1);
                  }
                  if(!_loc9_)
                  {
                     if(§§pop() >= §§pop())
                     {
                        if(!_loc10_)
                        {
                           §§push(0);
                           if(_loc10_)
                           {
                              §§push(-(§§pop() - 1 - 13 - 1 + 1) + 1 - 1);
                           }
                           if(!_loc10_)
                           {
                              §§push(uint(§§pop()));
                              if(!_loc9_)
                              {
                                 if(!_loc10_)
                                 {
                                    addr203:
                                    while(true)
                                    {
                                       §§push(_loc8_);
                                       if(!_loc9_)
                                       {
                                          §§push(256);
                                          if(_loc10_)
                                          {
                                             §§push(-((§§pop() - 110 + 59) * 8));
                                          }
                                       }
                                       break loop0;
                                    }
                                 }
                                 addr267:
                                 §§push(0);
                                 if(_loc9_)
                                 {
                                    §§push(§§pop() - 85 - 1 - 108 + 101);
                                 }
                              }
                              addr278:
                              _loc7_ = §§pop();
                              if(!_loc9_)
                              {
                                 loop2:
                                 while(_loc7_ < param1.length)
                                 {
                                    §§push(_loc8_);
                                    if(!_loc9_)
                                    {
                                       §§push(1);
                                       if(_loc9_)
                                       {
                                          §§push(-(§§pop() - 1 + 1 + 115 + 1 - 1 + 102));
                                       }
                                       §§push(§§pop() + §§pop());
                                       §§push(255);
                                       if(_loc9_)
                                       {
                                          §§push((-(§§pop() + 1) - 1) * 11 - 43 + 1);
                                       }
                                       §§push(§§pop() & §§pop());
                                       if(!_loc10_)
                                       {
                                          §§push(uint(§§pop()));
                                          if(_loc9_)
                                          {
                                          }
                                          addr327:
                                          §§push(§§pop() + _loc5_[_loc8_]);
                                          §§push(255);
                                          if(_loc9_)
                                          {
                                             §§push((§§pop() + 1 - 102 + 1 - 1 + 1) * 35);
                                          }
                                          §§push(§§pop() & §§pop());
                                       }
                                       §§push(uint(§§pop()));
                                       if(!_loc9_)
                                       {
                                          addr347:
                                          addr348:
                                          §§push(uint(_loc5_[_loc8_]));
                                       }
                                       if(!_loc10_)
                                       {
                                          _loc5_[_loc8_] = _loc5_[_loc6_];
                                          if(_loc9_)
                                          {
                                          }
                                          loop3:
                                          while(_loc10_)
                                          {
                                             while(true)
                                             {
                                                _loc5_[_loc6_] = _loc4_;
                                                if(!_loc9_)
                                                {
                                                   if(_loc10_)
                                                   {
                                                      break loop3;
                                                   }
                                                   addr375:
                                                   while(true)
                                                   {
                                                      §§push(_loc3_);
                                                      §§push(_loc7_);
                                                      §§push(param1[_loc7_]);
                                                      §§push(_loc5_);
                                                      §§push(_loc5_[_loc8_] + _loc5_[_loc6_]);
                                                      §§push(255);
                                                      if(_loc9_)
                                                      {
                                                         §§push(§§pop() + 57 - 63 + 4 + 39 - 1 + 66);
                                                      }
                                                      §§pop()[§§pop()] = §§pop() ^ §§pop()[§§pop() & §§pop()];
                                                      if(!_loc10_)
                                                      {
                                                         continue loop3;
                                                      }
                                                      break;
                                                   }
                                                }
                                                addr459:
                                                if(!_loc10_)
                                                {
                                                }
                                                continue loop2;
                                             }
                                          }
                                          §§push(_loc7_);
                                          if(!_loc9_)
                                          {
                                             §§push(Number(§§pop()));
                                             if(!_loc10_)
                                             {
                                                §§push(§§pop() + 1);
                                             }
                                             §§push(uint(§§pop()));
                                          }
                                          _loc7_ = §§pop();
                                          §§goto(addr459);
                                       }
                                       if(_loc10_)
                                       {
                                          §§goto(addr375);
                                       }
                                       §§goto(addr421);
                                    }
                                    if(!_loc9_)
                                    {
                                       §§push(_loc6_);
                                       if(!_loc9_)
                                       {
                                          §§goto(addr327);
                                       }
                                       §§goto(addr347);
                                    }
                                    §§goto(addr348);
                                 }
                              }
                              return _loc3_;
                           }
                           addr277:
                           §§goto(addr278);
                           §§push(uint(§§pop()));
                        }
                     }
                     else
                     {
                        _loc5_[_loc8_] = _loc8_;
                        if(!_loc9_)
                        {
                           §§push(_loc8_);
                           if(!_loc10_)
                           {
                              §§push(Number(§§pop()));
                              if(!_loc10_)
                              {
                                 §§push(§§pop() + 1);
                              }
                              §§push(uint(§§pop()));
                           }
                        }
                        continue;
                     }
                  }
                  while(true)
                  {
                     if(§§pop() >= §§pop())
                     {
                        if(!_loc9_)
                        {
                           §§push(0);
                           if(_loc10_)
                           {
                              §§push(-(-((§§pop() + 39) * 108) - 1 + 22) - 63);
                           }
                           if(!_loc10_)
                           {
                              §§push(uint(§§pop()));
                              if(!_loc9_)
                              {
                                 break loop0;
                              }
                              §§goto(addr278);
                           }
                           addr263:
                           §§push(uint(§§pop()));
                           if(!_loc10_)
                           {
                              §§goto(addr267);
                           }
                           §§goto(addr278);
                        }
                     }
                     else
                     {
                        §§push(_loc6_);
                        if(!_loc9_)
                        {
                           §§push(§§pop() + _loc5_[_loc8_] + param2.charCodeAt(_loc8_ % param2.length));
                           §§push(255);
                           if(_loc9_)
                           {
                              §§push(--(§§pop() * 30) + 57);
                           }
                           §§push(uint(§§pop() & §§pop()));
                           if(!_loc9_)
                           {
                              §§push(uint(_loc5_[_loc8_]));
                           }
                        }
                        if(!_loc10_)
                        {
                           _loc5_[_loc8_] = _loc5_[_loc6_];
                           if(!_loc10_)
                           {
                              _loc5_[_loc6_] = _loc4_;
                              if(_loc9_)
                              {
                              }
                           }
                           §§push(_loc8_);
                           if(!_loc9_)
                           {
                              §§push(Number(§§pop()));
                              if(!_loc10_)
                              {
                                 §§push(§§pop() + 1);
                              }
                              §§push(uint(§§pop()));
                           }
                        }
                        §§goto(addr203);
                     }
                  }
               }
               break;
            }
            if(_loc9_)
            {
            }
            §§goto(addr267);
         }
         §§push(0);
         if(_loc10_)
         {
            §§push(§§pop() * 74 - 1 + 1 + 1);
         }
         if(!_loc9_)
         {
            §§goto(addr263);
         }
         §§goto(addr277);
      }
   }
}
